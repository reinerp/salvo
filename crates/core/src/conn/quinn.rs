//! `QuinnListener` and utils.
use std::fmt::{self, Debug, Formatter};
use std::future::{Ready, ready};
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::{BoxFuture, FutureExt};
use futures_util::stream::{Once, once};
pub use quinn::ServerConfig;
use salvo_http3::quinn as http3_quinn;
use tokio_util::sync::CancellationToken;

use crate::conn::{Coupler, HttpBuilder, IntoConfigStream};
use crate::service::HyperHandler;

mod builder;
pub use builder::Builder;
mod listener;
pub use listener::{QuinnAcceptor, QuinnListener};

/// HTTP/3 connection.
#[allow(dead_code)]
pub struct QuinnConnection {
    inner: http3_quinn::Connection,
    raw: quinn::Connection,
}
impl QuinnConnection {
    pub(crate) fn new(raw: quinn::Connection) -> Self {
        Self {
            inner: http3_quinn::Connection::new(raw.clone()),
            raw,
        }
    }
    /// Get inner quinn connection.
    #[must_use]
    pub fn into_inner(self) -> http3_quinn::Connection {
        self.inner
    }

    /// Get the underlying Quinn connection.
    #[must_use]
    pub fn quinn(&self) -> &quinn::Connection {
        &self.raw
    }
}
impl Debug for QuinnConnection {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuinnConnection").finish()
    }
}
impl Deref for QuinnConnection {
    type Target = http3_quinn::Connection;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl DerefMut for QuinnConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// An accepted QUIC connection whose handshake is still in progress.
///
/// [`QuinnCoupler`] finishes the handshake on the connection's own task and starts HTTP/3 as
/// soon as the client's complete ClientHello has been processed, so the server's HTTP/3
/// SETTINGS travel with its first handshake flight (0.5-RTT data). Clients such as Chrome
/// wait for those SETTINGS before sending a WebTransport or extended CONNECT request, so this
/// saves a round trip on every new connection.
pub struct QuinnConnecting {
    connecting: quinn::Connecting,
    handshake_timeout: Option<Duration>,
}
impl QuinnConnecting {
    pub(crate) fn new(connecting: quinn::Connecting, handshake_timeout: Option<Duration>) -> Self {
        Self {
            connecting,
            handshake_timeout,
        }
    }

    /// Wait until HTTP/3 may start, then return the connection.
    ///
    /// The whole handshake is still bounded by `handshake_timeout`: a watchdog closes the
    /// connection if it has not completed by then.
    pub async fn establish(self) -> IoResult<QuinnConnection> {
        let Self {
            mut connecting,
            handshake_timeout,
        } = self;
        let deadline = handshake_timeout.map(|t| tokio::time::Instant::now() + t);
        let timed_out = || IoError::new(ErrorKind::TimedOut, "quic handshake timed out");
        // Wait for the client's complete ClientHello. quinn applies the client's transport
        // parameters (including its stream limits) while processing the same packet, before
        // this resolves. Streams must not be opened earlier: until then the peer's stream limit
        // is zero, and quinn 0.11 does not wake a pending `open_uni` when the transport
        // parameters later raise it, so HTTP/3 setup would stall forever.
        let handshake_data = connecting.handshake_data();
        let handshake_data = match deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, handshake_data)
                .await
                .map_err(|_| timed_out())?,
            None => handshake_data.await,
        };
        handshake_data.map_err(|e| IoError::other(e.to_string()))?;
        // Start HTTP/3 without waiting for the client's Finished. Only data we send is early:
        // quinn does not process the client's 1-RTT packets, and hence no requests, until the
        // handshake completes, and 0-RTT is refused unless the TLS config enables early data.
        let (conn, handshake_done) = match connecting.into_0rtt() {
            Ok(pair) => pair,
            // Unreachable for servers in quinn 0.11; fall back to a full handshake.
            Err(connecting) => {
                let conn = match deadline {
                    Some(deadline) => tokio::time::timeout_at(deadline, connecting)
                        .await
                        .map_err(|_| timed_out())?,
                    None => connecting.await,
                };
                return conn
                    .map(QuinnConnection::new)
                    .map_err(|e| IoError::other(e.to_string()));
            }
        };
        if let Some(deadline) = deadline {
            let watched = conn.clone();
            tokio::spawn(async move {
                // `handshake_done` also resolves if the connection closes first.
                if tokio::time::timeout_at(deadline, handshake_done)
                    .await
                    .is_err()
                {
                    watched.close(0u32.into(), b"handshake timed out");
                }
            });
        }
        Ok(QuinnConnection::new(conn))
    }
}
impl Debug for QuinnConnecting {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuinnConnecting").finish()
    }
}

/// QUIC connection coupler.
pub struct QuinnCoupler;
impl Coupler for QuinnCoupler {
    type Stream = QuinnConnecting;

    fn couple(
        &self,
        stream: Self::Stream,
        handler: HyperHandler,
        builder: Arc<HttpBuilder>,
        graceful_stop_token: Option<CancellationToken>,
    ) -> BoxFuture<'static, IoResult<()>> {
        async move {
            let conn = stream.establish().await?;
            builder
                .quinn
                .serve_connection(conn, handler, graceful_stop_token)
                .await
        }
        .boxed()
    }
}
impl Debug for QuinnCoupler {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuinnCoupler").finish()
    }
}

impl IntoConfigStream<Self> for ServerConfig {
    type Stream = Once<Ready<Self>>;

    fn into_stream(self) -> Self::Stream {
        once(ready(self))
    }
}

impl IntoConfigStream<ServerConfig> for quinn::crypto::rustls::QuicServerConfig {
    type Stream = Once<Ready<ServerConfig>>;

    fn into_stream(self) -> Self::Stream {
        once(ready(ServerConfig::with_crypto(Arc::new(self))))
    }
}
