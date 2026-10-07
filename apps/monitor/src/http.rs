//! Минимальный HTTP/1.1 JSON-RPC клиент (только `http://`).
//!
//! Достаточен для локального validator и RPC за доверенным TLS-терминатором.
//! Прямое подключение к публичному `https://` RPC — открытый пункт (нужен
//! TLS-адаптер); Monitor отвергает `https://` явно, а не молча.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct HttpUrl {
    host: String,
    port: u16,
    path: String,
}

impl HttpUrl {
    pub fn parse(url: &str) -> Result<Self, String> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| format!("only http:// RPC URLs are supported: {url}"))?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse::<u16>().map_err(|_| format!("bad port in {url}"))?,
            ),
            None => (authority.to_string(), 80),
        };
        if host.is_empty() {
            return Err(format!("empty host in {url}"));
        }
        Ok(Self {
            host,
            port,
            path: path.to_string(),
        })
    }
}

pub fn post_json(url: &HttpUrl, body: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    let addr = (url.host.as_str(), url.port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve: {e}"))?
        .next()
        .ok_or("resolve: no address")?;
    let mut stream =
        TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    let head = format!(
        "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        url.path,
        url.host,
        url.port,
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    stream.write_all(body).map_err(|e| format!("write: {e}"))?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("read: {e}"))?;
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> Result<Vec<u8>, String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("malformed HTTP response")?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| "non-UTF-8 HTTP head")?;
    let body = &raw[split + 4..];
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or("");
    let code = status.split_whitespace().nth(1).unwrap_or("");
    if code != "200" {
        return Err(format!("HTTP status {status}"));
    }
    let mut chunked = false;
    let mut length: Option<usize> = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            if k == "transfer-encoding" && v.eq_ignore_ascii_case("chunked") {
                chunked = true;
            } else if k == "content-length" {
                length = Some(v.parse().map_err(|_| "bad content-length")?);
            }
        }
    }
    if chunked {
        return dechunk(body);
    }
    match length {
        Some(n) if body.len() >= n => Ok(body[..n].to_vec()),
        Some(_) => Err("truncated HTTP body".into()),
        None => Ok(body.to_vec()),
    }
}

fn dechunk(mut body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let eol = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("truncated chunk header")?;
        let size_text = std::str::from_utf8(&body[..eol]).map_err(|_| "bad chunk header")?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| "bad chunk size")?;
        body = &body[eol + 2..];
        if size == 0 {
            return Ok(out);
        }
        if body.len() < size + 2 {
            return Err("truncated chunk".into());
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_urls_and_rejects_https() {
        let u = HttpUrl::parse("http://127.0.0.1:8899").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("127.0.0.1", 8899, "/")
        );
        assert!(HttpUrl::parse("https://api.devnet.solana.com").is_err());
    }

    #[test]
    fn decodes_length_and_chunked_bodies() {
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap(),
            b"{}"
        );
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n{\r\n1\r\n}\r\n0\r\n\r\n").unwrap(),
            b"{}"
        );
        assert!(parse_response(b"HTTP/1.1 500 Oops\r\n\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{}").is_err());
    }
}
