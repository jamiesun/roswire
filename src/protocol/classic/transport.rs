use crate::error::{RosWireError, RosWireResult};
use crate::protocol::tls::{client_config, TlsFingerprint};
use rustls::{ClientConnection, StreamOwned};
use rustls_pki_types::ServerName;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

pub trait ApiStream: Read + Write + Send {}

impl<T> ApiStream for T where T: Read + Write + Send {}

#[derive(Debug)]
pub struct TcpApiStream {
    inner: TcpStream,
}

impl TcpApiStream {
    pub fn connect(host: &str, port: u16, timeout: Duration) -> RosWireResult<Self> {
        Ok(Self {
            inner: connect_tcp_stream(host, port, timeout, "RouterOS API")?,
        })
    }
}

pub struct TlsApiStream {
    inner: StreamOwned<ClientConnection, TcpStream>,
}

impl TlsApiStream {
    pub fn connect(
        host: &str,
        port: u16,
        timeout: Duration,
        fingerprint: Option<&TlsFingerprint>,
    ) -> RosWireResult<Self> {
        let stream = connect_tcp_stream(host, port, timeout, "RouterOS API TLS")?;
        let server_name_host = tls_server_name_host(host);
        let server_name = ServerName::try_from(server_name_host.clone()).map_err(|error| {
            Box::new(tls_error(format!(
                "invalid RouterOS API TLS server name `{server_name_host}`: {error}",
            )))
        })?;
        let config = client_config(fingerprint);
        let connection = ClientConnection::new(config, server_name).map_err(|error| {
            Box::new(tls_error(format!(
                "failed to initialize RouterOS API TLS connection: {error}",
            )))
        })?;
        let mut inner = StreamOwned::new(connection, stream);
        while inner.conn.is_handshaking() {
            inner.conn.complete_io(&mut inner.sock).map_err(|error| {
                Box::new(tls_error(format!(
                    "RouterOS API TLS handshake failed at {host}:{port}: {error}",
                )))
            })?;
        }

        Ok(Self { inner })
    }
}

fn tls_server_name_host(host: &str) -> String {
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);

    if unbracketed.contains(':') {
        unbracketed
            .split_once('%')
            .map(|(address, _)| address)
            .unwrap_or(unbracketed)
            .to_owned()
    } else {
        unbracketed.to_owned()
    }
}

impl Read for TcpApiStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buffer)
    }
}

impl Write for TcpApiStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl Read for TlsApiStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buffer)
    }
}

impl Write for TlsApiStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn connect_tcp_stream(
    host: &str,
    port: u16,
    timeout: Duration,
    service_label: &str,
) -> RosWireResult<TcpStream> {
    let mut addresses = (host, port).to_socket_addrs().map_err(|error| {
        Box::new(network_error(format!(
            "failed to resolve {service_label} address: {error}",
        )))
    })?;

    let address = addresses.next().ok_or_else(|| {
        Box::new(network_error(format!(
            "failed to resolve {service_label} address: no socket addresses returned",
        )))
    })?;

    let stream = TcpStream::connect_timeout(&address, timeout).map_err(|error| {
        Box::new(network_error(format!(
            "failed to connect to {service_label} at {host}:{port}: {error}",
        )))
    })?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| Box::new(map_io_error("set API read timeout", error)))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| Box::new(map_io_error("set API write timeout", error)))?;

    Ok(stream)
}

pub fn map_io_error(operation: &str, error: std::io::Error) -> RosWireError {
    network_error(format!(
        "RouterOS API transport I/O error while attempting to {operation}: {error}",
    ))
}

fn network_error(message: impl Into<String>) -> RosWireError {
    RosWireError::network(message)
}

fn tls_error(message: impl Into<String>) -> RosWireError {
    RosWireError::tls(message)
}

#[cfg(test)]
mod tests {
    use super::{map_io_error, tls_server_name_host, ApiStream, TlsApiStream};
    use crate::error::ErrorCode;
    use std::io::{Cursor, Read, Result, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    struct FakeApiStream {
        rx: Cursor<Vec<u8>>,
        tx: Vec<u8>,
    }

    impl FakeApiStream {
        fn new(rx: Vec<u8>) -> Self {
            Self {
                rx: Cursor::new(rx),
                tx: Vec::new(),
            }
        }
    }

    impl Read for FakeApiStream {
        fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
            self.rx.read(buffer)
        }
    }

    impl Write for FakeApiStream {
        fn write(&mut self, buffer: &[u8]) -> Result<usize> {
            self.tx.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    fn assert_api_stream<T: ApiStream>(_stream: &T) {}

    #[test]
    fn fake_stream_can_satisfy_transport_boundary() {
        let stream = FakeApiStream::new(Vec::new());
        assert_api_stream(&stream);
    }

    #[test]
    fn io_errors_map_to_network_error() {
        let error = map_io_error(
            "read sentence",
            std::io::Error::from(std::io::ErrorKind::TimedOut),
        );

        assert_eq!(error.error_code, ErrorCode::NetworkError);
        assert!(error.message.contains("read sentence"));
    }

    #[test]
    fn tls_server_name_host_strips_ipv6_zone_identifier() {
        assert_eq!(tls_server_name_host("fe80::1%en0"), "fe80::1");
        assert_eq!(tls_server_name_host("[fe80::1%en0]"), "fe80::1");
        assert_eq!(tls_server_name_host("router.example"), "router.example");
    }

    #[test]
    fn tls_handshake_failure_maps_to_tls_error() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener
            .local_addr()
            .expect("local addr should exist")
            .port();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("connection should arrive");
            stream
                .write_all(b"not a tls server")
                .expect("fixture response should write");
        });

        let error = match TlsApiStream::connect("127.0.0.1", port, Duration::from_millis(500), None)
        {
            Ok(_) => panic!("plain TCP server should fail TLS handshake"),
            Err(error) => error,
        };
        handle.join().expect("server thread should finish");

        assert_eq!(error.error_code, ErrorCode::TlsError);
        assert!(error.message.contains("TLS handshake failed"));
    }
}
