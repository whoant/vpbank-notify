//! One-shot HTTP/1.1 responder for tests that exercise the real reqwest client.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Accepts one connection, answers it, and returns the lowercased request head.
///
/// `headers` are extra raw header lines, each ending in `\r\n`.
pub(crate) async fn exchange(
    listener: &TcpListener,
    status: &str,
    headers: &str,
    body: &str,
) -> String {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut request = Vec::new();
    let mut buffer = [0; 2048];
    loop {
        let read = socket.read(&mut buffer).await.unwrap();
        request.extend_from_slice(&buffer[..read]);
        if read == 0 || request.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let response = format!(
        "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    socket.write_all(response.as_bytes()).await.unwrap();
    String::from_utf8_lossy(&request).to_ascii_lowercase()
}
