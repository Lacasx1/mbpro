use std::env;
use std::fs::File;
use std::io::{BufReader, Error};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{timeout, Duration};
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let port = get_port();
    let status = get_status();
    let use_udp = has_arg("-u");
    let use_quic = has_arg("-q");
    let tls_acceptor = if has_arg("-t") { Some(load_tls_acceptor()?) } else { None };
    let quic_port = get_quic_port();

    println!("[Mpro] Multi-protocolo v2.6.1");
    println!("[HTTP Security{}] Porta: {}", if tls_acceptor.is_some() { "+TLS" } else { "" }, port);

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
    println!("Aguardando conexões HTTP Security em {}...", port);
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
                        eprintln!("[HTTP] Cliente {} desconectado: {}", addr, e);
                    }
                });
            }
            Err(e) => eprintln!("[HTTP] Erro ao aceitar conexão: {}", e),
        }
    }
}

async fn handle_client(
    client_stream: TcpStream,
    status: &str,
    tls_acceptor: Option<TlsAcceptor>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(acceptor) = tls_acceptor {
        let tls_stream = acceptor.accept(client_stream).await?;
        handle_http_security(tls_stream, status).await
    } else {
        handle_http_security(client_stream, status).await
    }
}

async fn handle_http_security<S>(
    mut client: S,
    status: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // HTTP Security não é WebSocket: ler o cabeçalho HTTP até CRLFCRLF sem
    // exigir Upgrade/Sec-WebSocket-Key e preservar dados enviados junto ao cabeçalho.
    let mut request = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        if let Some(pos) = find_header_end(&request) {
            break pos;
        }
        if request.len() >= 16 * 1024 {
            return Err("Cabeçalho HTTP maior que 16 KiB".into());
        }
        let n = timeout(Duration::from_secs(10), client.read(&mut chunk)).await??;
        if n == 0 {
            return Ok(());
        }
        request.extend_from_slice(&chunk[..n]);
    };

    let header = String::from_utf8_lossy(&request[..header_end]);
    let lowered = header.to_ascii_lowercase();
    let backend_port = if lowered.contains("x-mpro-backend: vpn")
        || lowered.contains("/vpn")
        || lowered.contains("1194")
    {
        1194
    } else {
        22
    };
    let mut backend = timeout(
        Duration::from_secs(5),
        TcpStream::connect(("127.0.0.1", backend_port)),
    )
    .await??;

    // Manter o texto configurado no menu (ex.: "ws") como reason phrase,
    // mas enviar apenas uma resposta HTTP; nunca concatenar um segundo 200.
    let reason = safe_reason_phrase(status);
    let response = format!("HTTP/1.1 101 {}\r\n\r\n", reason);
    client.write_all(response.as_bytes()).await?;
    client.flush().await?;

    // Se o app enviou dados após o fim do cabeçalho no mesmo pacote, não os perde.
    let body_start = header_end + 4;
    if request.len() > body_start {
        backend.write_all(&request[body_start..]).await?;
    }

    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut backend_read, mut backend_write) = backend.into_split();
    let client_to_backend = tokio::io::copy(&mut client_read, &mut backend_write);
    let backend_to_client = tokio::io::copy(&mut backend_read, &mut client_write);
    let _ = tokio::join!(client_to_backend, backend_to_client);
    Ok(())
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}

fn safe_reason_phrase(value: &str) -> String {
    let filtered: String = value
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect();
    if filtered.trim().is_empty() {
        "Mpro".to_string()
    } else {
        filtered.trim().to_string()
    }
}

fn load_tls_acceptor() -> Result<TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    let mut cert_reader = BufReader::new(File::open("/opt/mpro/cert.pem")?);
    let certificates = rustls_pemfile::certs(&mut cert_reader)?
        .into_iter()
        .map(Certificate)
        .collect();

    let mut key_reader = BufReader::new(File::open("/opt/mpro/key.pem")?);
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key_reader)?;
    if keys.is_empty() {
        let mut key_reader = BufReader::new(File::open("/opt/mpro/key.pem")?);
        keys = rustls_pemfile::rsa_private_keys(&mut key_reader)?;
    }
    let key = keys
        .into_iter()
        .next()
        .ok_or("Nenhuma chave privada válida em /opt/mpro/key.pem")?;

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
