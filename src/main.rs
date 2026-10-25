use std::env;
use std::fs::File;
use std::io::{BufReader, Error};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{timeout, Duration};
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::http::header::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::accept_hdr_async;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let port = get_port();
    let status = get_status();
    let use_udp = has_arg("-u");
    let use_quic = has_arg("-q");
    let tls_acceptor = if has_arg("-t") { Some(load_tls_acceptor()?) } else { None };
    let quic_port = get_quic_port();

    println!("[Mpro] Multi-protocolo v2.6.0");
    println!("[TCP/WebSocket{}] Porta: {}", if tls_acceptor.is_some() { "+TLS" } else { "" }, port);

    if use_udp {
        println!("[UDP] Habilitado na porta: {}", port);
        let status_udp = status.clone();
        tokio::spawn(async move {
            if let Err(e) = start_udp(port, &status_udp).await {
                println!("[UDP] Erro: {}", e);
            }
        });
    }

    if use_quic {
        println!("[QUIC] Habilitado na porta: {} (implementação ainda não ativa)", quic_port);
    }

    let listener = TcpListener::bind(format!("[::]:{}", port)).await?;
    println!("Aguardando conexões WebSocket em {}...", port);
    start_http(listener, status, tls_acceptor).await;
    Ok(())
}

async fn start_http(listener: TcpListener, status: String, tls_acceptor: Option<TlsAcceptor>) {
    let status = Arc::new(status);
    loop {
        match listener.accept().await {
            Ok((client_stream, addr)) => {
                let status = status.clone();
                let tls_acceptor = tls_acceptor.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(client_stream, &status, tls_acceptor).await {
                        eprintln!("[TCP] Cliente {} desconectado: {}", addr, e);
                    }
                });
            }
            Err(e) => eprintln!("[TCP] Erro ao aceitar conexão: {}", e),
        }
    }
}

async fn handle_client(client_stream: TcpStream, status: &str, tls_acceptor: Option<TlsAcceptor>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(acceptor) = tls_acceptor {
        let tls_stream = acceptor.accept(client_stream).await?;
        handle_websocket(tls_stream, status).await
    } else {
        handle_websocket(client_stream, status).await
    }
}

async fn handle_websocket<S>(client_stream: S, status: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // O handler de upgrade envia exatamente uma resposta 101 válida. O texto de -s
    // vai em X-Mpro-Status; não é usado como motivo HTTP nem seguido por um 200.
    let selected_port = Arc::new(Mutex::new(22_u16));
    let selected_port_for_callback = selected_port.clone();
    let status_header = HeaderValue::from_str(status)
        .unwrap_or_else(|_| HeaderValue::from_static("Mpro"));

    let websocket = accept_hdr_async(client_stream, move |request: &Request, mut response: Response| {
        let backend = request.headers().get("x-mpro-backend")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_else(|| request.uri().path());
        let port = if backend.to_ascii_lowercase().contains("vpn")
            || backend.contains("1194") {
            1194
        } else {
            22
        };
        if let Ok(mut selected) = selected_port_for_callback.lock() {
            *selected = port;
        }
        response.headers_mut().insert("X-Mpro-Status", status_header.clone());
        Ok(response)
    }).await?;

    let backend_port = selected_port.lock().map(|p| *p).unwrap_or(22);
    let mut backend = timeout(Duration::from_secs(5), TcpStream::connect(("127.0.0.1", backend_port))).await??;
    println!("[WS] Upgrade concluído; túnel para 127.0.0.1:{}", backend_port);

    let (mut ws_sink, mut ws_stream) = websocket.split();
    let (mut backend_read, mut backend_write) = backend.split();
    let mut buffer = [0_u8; 8192];

    loop {
        tokio::select! {
            ws_message = ws_stream.next() => {
                match ws_message {
                    Some(Ok(Message::Binary(data))) => backend_write.write_all(&data).await?,
                    Some(Ok(Message::Text(data))) => backend_write.write_all(data.as_bytes()).await?,
                    Some(Ok(Message::Ping(data))) => ws_sink.send(Message::Pong(data)).await?,
                    Some(Ok(Message::Pong(_))) => {},
                    Some(Ok(Message::Close(frame))) => {
                        let _ = ws_sink.send(Message::Close(frame)).await;
                        break;
                    },
                    Some(Ok(_)) => {},
                    Some(Err(e)) => return Err(Box::new(e)),
                    None => break,
                }
            }
            read_result = backend_read.read(&mut buffer) => {
                let n = read_result?;
                if n == 0 {
                    let _ = ws_sink.send(Message::Close(None)).await;
                    break;
                }
                ws_sink.send(Message::Binary(buffer[..n].to_vec())).await?;
            }
        }
    }
    Ok(())
}

fn load_tls_acceptor() -> Result<TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    let mut cert_reader = BufReader::new(File::open("/opt/mpro/cert.pem")?);
    let certificates = rustls_pemfile::certs(&mut cert_reader)?
        .into_iter().map(Certificate).collect();

    let mut key_reader = BufReader::new(File::open("/opt/mpro/key.pem")?);
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key_reader)?;
    if keys.is_empty() {
        let mut key_reader = BufReader::new(File::open("/opt/mpro/key.pem")?);
        keys = rustls_pemfile::rsa_private_keys(&mut key_reader)?;
    }
    let key = keys.into_iter().next().ok_or("Nenhuma chave privada válida em /opt/mpro/key.pem")?;

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certificates, PrivateKey(key))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

async fn start_udp(port: u16, _status: &str) -> Result<(), Error> {
    let socket = UdpSocket::bind(format!("[::]:{}", port)).await?;
    let mut buf = [0u8; 2048];
    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        println!("[UDP] {} bytes de {} (UDP ainda não encaminhado)", len, addr);
    }
}

fn get_port() -> u16 {
    let args: Vec<String> = env::args().collect();
    for i in 1..args.len() {
        if (args[i] == "--port" || args[i] == "-p") && i + 1 < args.len() {
            return args[i + 1].parse().unwrap_or(8080);
        }
    }
    8080
}

fn get_quic_port() -> u16 {
    let args: Vec<String> = env::args().collect();
    for i in 1..args.len() {
        if args[i] == "--quic-port" && i + 1 < args.len() {
            return args[i + 1].parse().unwrap_or(8001);
        }
    }
    8001
}

fn get_status() -> String {
    let args: Vec<String> = env::args().collect();
    for i in 1..args.len() {
        if (args[i] == "--status" || args[i] == "-s") && i + 1 < args.len() {
            return args[i + 1].clone();
        }
    }
    "@Mpro".to_string()
}

fn has_arg(arg: &str) -> bool {
    env::args().any(|a| a == arg)
}
