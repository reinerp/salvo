//! Regression tests for accepting QUIC connections. Clients connect through a local UDP relay
//! that delays packets, so handshakes are observably in flight, and that can hold back the
//! second datagram of a ClientHello: the client pads its ClientHello over two datagrams, as
//! browsers with post-quantum key shares do.
#![cfg(all(feature = "server", feature = "quinn", feature = "ring"))]
#![allow(clippy::unwrap_used)]
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use salvo_core::conn::rustls::{Keycert, RustlsConfig};
use salvo_core::conn::{Listener, QuinnListener, TcpListener};
use salvo_core::proto::quinn;
use salvo_core::{Router, Server};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep, sleep_until, timeout};

#[derive(Clone, Copy, Default)]
struct Relay {
    one_way: Duration,
    /// Extra delay for the client's second datagram.
    hold_second: Duration,
    /// Drop the client's datagrams once the server has replied, so the server never sees
    /// the client's Finished.
    blackhole_after_reply: bool,
}

/// Forward `packets` in FIFO order, each `delay` after it arrived.
fn delay_line(
    delay: Duration,
    send: impl Fn(&[u8]) + Send + 'static,
) -> mpsc::UnboundedSender<Vec<u8>> {
    let (tx, mut rx) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
    tokio::spawn(async move {
        while let Some((due, packet)) = rx.recv().await {
            sleep_until(due).await;
            send(&packet);
        }
    });
    let (in_tx, mut in_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Some(packet) = in_rx.recv().await {
            if tx.send((Instant::now() + delay, packet)).is_err() {
                break;
            }
        }
    });
    in_tx
}

impl Relay {
    /// Relay one client's datagrams to `server`; returns the address the client dials.
    async fn start(self, server: SocketAddr) -> SocketAddr {
        let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        back.connect(server).await.unwrap();
        let client = Arc::new(Mutex::new(None::<SocketAddr>));
        let replied = Arc::new(AtomicBool::new(false));
        let to_server = {
            let back = back.clone();
            delay_line(self.one_way, move |p| {
                let _ = back.try_send(p);
            })
        };
        let to_client = {
            let (front, client) = (front.clone(), client.clone());
            delay_line(self.one_way, move |p| {
                if let Some(to) = *client.lock().unwrap() {
                    let _ = front.try_send_to(p, to);
                }
            })
        };
        let addr = front.local_addr().unwrap();
        {
            let (front, back, client, replied) =
                (front.clone(), back.clone(), client, replied.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                let mut count = 0;
                while let Ok((n, from)) = front.recv_from(&mut buf).await {
                    *client.lock().unwrap() = Some(from);
                    count += 1;
                    if self.blackhole_after_reply && replied.load(Ordering::SeqCst) {
                        continue;
                    }
                    let packet = buf[..n].to_vec();
                    if count == 2 && !self.hold_second.is_zero() {
                        let (back, delay) = (back.clone(), self.one_way + self.hold_second);
                        tokio::spawn(async move {
                            sleep(delay).await;
                            let _ = back.send(&packet).await;
                        });
                    } else {
                        let _ = to_server.send(packet);
                    }
                }
            });
        }
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            while let Ok(n) = back.recv(&mut buf).await {
                replied.store(true, Ordering::SeqCst);
                let _ = to_client.send(buf[..n].to_vec());
            }
        });
        addr
    }
}

async fn start_server(port: u16) -> SocketAddr {
    // salvo 0.96 takes the process-level rustls provider.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = include_bytes!("../certs/cert.pem").to_vec();
    let key = include_bytes!("../certs/key.pem").to_vec();
    let config = RustlsConfig::new(Keycert::new().cert(cert.as_slice()).key(key.as_slice()));
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let acceptor = QuinnListener::new(config.clone(), addr)
        .join(TcpListener::new(addr).rustls(config))
        .bind()
        .await;
    tokio::spawn(Server::new(acceptor).serve(Router::new()));
    addr
}

fn client() -> quinn::Endpoint {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    let chain = include_bytes!("../certs/chain.pem");
    for cert in CertificateDer::pem_slice_iter(chain) {
        roots.add(cert.unwrap()).unwrap();
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // Enough ALPN padding to split the ClientHello over two datagrams.
    tls.alpn_protocols = (0..60)
        .map(|i| format!("padding-protocol-{i:03}").into_bytes())
        .chain([b"h3".to_vec()])
        .collect();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    endpoint
}

/// Wait for the server's HTTP/3 control stream, which carries its SETTINGS.
async fn control_stream(conn: &quinn::Connection, limit: Duration) -> Result<(), String> {
    let mut recv = timeout(limit, conn.accept_uni())
        .await
        .map_err(|_| format!("no server stream within {limit:?}"))?
        .map_err(|e| e.to_string())?;
    let mut ty = [0u8; 1];
    recv.read_exact(&mut ty).await.map_err(|e| e.to_string())?;
    assert_eq!(
        ty[0], 0x00,
        "first server stream should be the control stream"
    );
    Ok(())
}

#[tokio::test]
async fn settings_ride_the_first_flight_when_client_hello_is_split() {
    let server = start_server(6981).await;
    let endpoint = client();
    for _ in 0..5 {
        let relay = Relay {
            one_way: Duration::from_millis(100),
            hold_second: Duration::from_millis(30),
            ..Default::default()
        };
        let conn = endpoint
            .connect(relay.start(server).await, "localhost")
            .unwrap()
            .await
            .unwrap();
        // SETTINGS are sent as 0.5-RTT data, so they arrive with the server's handshake
        // flight rather than a round trip after the client's Finished.
        control_stream(&conn, Duration::from_millis(100))
            .await
            .unwrap();
        conn.close(0u32.into(), b"");
    }
}

#[tokio::test]
async fn tcp_accept_does_not_drop_quic_handshake() {
    let server = start_server(6982).await;
    let endpoint = client();
    let relay = Relay {
        one_way: Duration::from_millis(100),
        ..Default::default()
    };
    let dial = relay.start(server).await;
    let tcp = tokio::spawn(async move {
        sleep(Duration::from_millis(150)).await;
        tokio::net::TcpStream::connect(server).await.unwrap()
    });
    let conn = timeout(
        Duration::from_secs(5),
        endpoint.connect(dial, "localhost").unwrap(),
    )
    .await
    .expect("QUIC handshake should complete")
    .unwrap();
    control_stream(&conn, Duration::from_secs(2)).await.unwrap();
    drop(tcp.await.unwrap());
}

#[tokio::test]
async fn stalled_handshake_does_not_block_other_connections() {
    let server = start_server(6983).await;
    let stalled = client();
    let relay = Relay {
        one_way: Duration::from_millis(10),
        blackhole_after_reply: true,
        ..Default::default()
    };
    let dial = relay.start(server).await;
    let _stalled = stalled.connect(dial, "localhost").unwrap();
    sleep(Duration::from_millis(200)).await;

    let endpoint = client();
    let relay = Relay {
        one_way: Duration::from_millis(10),
        ..Default::default()
    };
    let conn = timeout(
        Duration::from_secs(2),
        endpoint
            .connect(relay.start(server).await, "localhost")
            .unwrap(),
    )
    .await
    .expect("a stalled handshake must not delay other connections")
    .unwrap();
    control_stream(&conn, Duration::from_secs(1)).await.unwrap();
}
