use crate::{TcpConnection, TlsListenerBuilder, TlsListenerConfig};
use async_std_openssl::SslStream;
use async_std_openssl::SslStreamWrapper;

use openssl::ssl::{Ssl, SslAcceptor, SslFiletype, SslMethod};
use tide::listener::ListenInfo;
use tide::listener::{Listener, ToListener};
use tide::Server;

use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::{io, task};

use std::fmt::{self, Debug, Display, Formatter};
use std::pin::Pin;
use std::time::Duration;

/// The primary type for this crate
pub struct TlsListener<State> {
    connection: TcpConnection,
    config: TlsListenerConfig,
    acceptor: Option<SslAcceptor>,
    server: Option<Server<State>>,
    tcp_nodelay: Option<bool>,
    tcp_ttl: Option<u32>,
}

impl<State> Debug for TlsListener<State> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsListener")
            .field(&"connection", &self.connection)
            .field(
                &"acceptor",
                if self.acceptor.is_some() {
                    &"Some(SslAcceptor)"
                } else {
                    &"None"
                },
            )
            .field(
                &"server",
                if self.server.is_some() {
                    &"Some(Server<State>)"
                } else {
                    &"None"
                },
            )
            .field("tcp_ttl", &self.tcp_ttl)
            .field("tcp_nodelay", &self.tcp_nodelay)
            .finish()
    }
}

impl<State> TlsListener<State> {
    pub(crate) fn new(
        connection: TcpConnection,
        config: TlsListenerConfig,
        tcp_nodelay: Option<bool>,
        tcp_ttl: Option<u32>,
    ) -> Self {
        Self {
            connection,
            config,
            acceptor: None,
            server: None,
            tcp_nodelay,
            tcp_ttl,
        }
    }
    /// The primary entrypoint to create a TlsListener. See
    /// [TlsListenerBuilder](crate::TlsListenerBuilder) for more
    /// configuration options.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tide_openssl::TlsListener;
    /// let listener = TlsListener::<()>::build()
    ///     .addrs("localhost:4433")
    ///     .cert("./tls/localhost-4433.cert")
    ///     .key("./tls/localhost-4433.key")
    ///     .finish();
    /// ```
    pub fn build() -> TlsListenerBuilder<State> {
        TlsListenerBuilder::new()
    }

    async fn configure(&mut self) -> io::Result<()> {
        // TODO: Support ServerConfig and CustomTlsAcceptor
        match &self.config {
            TlsListenerConfig::Paths { cert, key } => {
                let mut acceptor = SslAcceptor::mozilla_modern_v5(SslMethod::tls())
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                acceptor
                    .set_private_key_file(key, SslFiletype::PEM)
                    .and_then(|_| acceptor.set_certificate_chain_file(cert))
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                self.acceptor = Some(acceptor.build());

                Ok(())
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "need exactly one of cert + key",
                ))
            }
        }

        // self.config = match std::mem::take(&mut self.config) {
        //     TlsListenerConfig::Paths { cert, key } => {
        //         let certs = load_certs(&cert)?;
        //         let mut keys = load_keys(&key)?;
        //         let mut config = ServerConfig::new(NoClientAuth::new());
        //         config
        //             .set_single_cert(certs, keys.remove(0))
        //             .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

        //         TlsListenerConfig::Acceptor(Arc::new(StandardTlsAcceptor(TlsAcceptor::from(
        //             Arc::new(config),
        //         ))))
        //     }

        //     TlsListenerConfig::ServerConfig(config) => TlsListenerConfig::Acceptor(Arc::new(
        //         StandardTlsAcceptor(TlsAcceptor::from(Arc::new(config))),
        //     )),

        //     other @ TlsListenerConfig::Acceptor(_) => other,

        //     TlsListenerConfig::Unconfigured => {
        //         return Err(io::Error::new(
        //             io::ErrorKind::Other,
        //             "could not configure tlslistener",
        //         ));
        //     }
        // };
    }

    // fn acceptor(&self) -> Option<&Arc<dyn CustomTlsAcceptor>> {
    //     match self.config {
    //         TlsListenerConfig::Acceptor(ref a) => Some(a),
    //         _ => None,
    //     }
    // }

    fn tcp(&self) -> Option<&TcpListener> {
        match self.connection {
            TcpConnection::Connected(ref t) => Some(t),
            _ => None,
        }
    }

    async fn connect(&mut self) -> io::Result<()> {
        if let TcpConnection::Addrs(addrs) = &self.connection {
            let tcp = TcpListener::bind(&addrs[..]).await?;
            self.connection = TcpConnection::Connected(tcp);
        }
        Ok(())
    }
}

fn handle_tls<State: Clone + Send + Sync + 'static>(
    app: Server<State>,
    stream: TcpStream,
    acceptor: SslAcceptor,
) {
    task::spawn(async move {
        let local_addr = stream.local_addr().ok();
        let peer_addr = stream.peer_addr().ok();

        let ssl_stream = Ssl::new(acceptor.context()).and_then(|ssl| SslStream::new(ssl, stream));
        let mut ssl_stream = match ssl_stream {
            Ok(s) => s,
            Err(e) => {
                tide::log::error!("ssl error", { error: e.to_string() });
                return;
            }
        };

        match Pin::new(&mut ssl_stream).accept().await {
            Ok(_) => {
                let stream = SslStreamWrapper::new(ssl_stream);
                let fut = async_h1::accept(stream, |mut req| async {
                    if req.url_mut().set_scheme("https").is_err() {
                        tide::log::error!("unable to set https scheme on url", { url: req.url().to_string() });
                    }

                    req.set_local_addr(local_addr);
                    req.set_peer_addr(peer_addr);
                    app.respond(req).await
                });

                if let Err(error) = fut.await {
                    tide::log::error!("async-h1 error", { error: error.to_string() });
                }
            }
            Err(tls_error) => {
                tide::log::error!("tls error", { error: tls_error.to_string() });
            }
        }
    });
}

impl<State: Clone + Send + Sync + 'static> ToListener<State> for TlsListener<State> {
    type Listener = Self;
    fn to_listener(self) -> io::Result<Self::Listener> {
        Ok(self)
    }
}

impl<State: Clone + Send + Sync + 'static> ToListener<State> for TlsListenerBuilder<State> {
    type Listener = TlsListener<State>;
    fn to_listener(self) -> io::Result<Self::Listener> {
        self.finish()
    }
}

#[tide::utils::async_trait]
impl<State: Clone + Send + Sync + 'static> Listener<State> for TlsListener<State> {
    async fn bind(&mut self, server: Server<State>) -> io::Result<()> {
        self.configure().await?;
        self.connect().await?;
        self.server = Some(server);
        Ok(())
    }

    async fn accept(&mut self) -> io::Result<()> {
        let listener = self
            .tcp()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "accept - listener"))?;
        let mut incoming = listener.incoming();
        let acceptor = self
            .acceptor
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "accept - acceptor"))?;
        let server = self
            .server
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "accept - server"))?;

        while let Some(stream) = incoming.next().await {
            match stream {
                Err(ref e) if is_transient_error(e) => continue,

                Err(error) => {
                    let delay = Duration::from_millis(500);
                    tide::log::error!("Error: {}. Pausing for {:?}.", error, delay);
                    task::sleep(delay).await;
                    continue;
                }

                Ok(stream) => {
                    if let Some(nodelay) = self.tcp_nodelay {
                        stream.set_nodelay(nodelay)?;
                    }

                    if let Some(ttl) = self.tcp_ttl {
                        stream.set_ttl(ttl)?;
                    }

                    handle_tls(server.clone(), stream, acceptor.clone())
                }
            };
        }
        Ok(())
    }

    fn info(&self) -> Vec<ListenInfo> {
        vec![ListenInfo::new(
            self.connection.to_string(),
            String::from("tcp"),
            true,
        )]
    }
}

fn is_transient_error(e: &io::Error) -> bool {
    use io::ErrorKind::*;
    matches!(
        e.kind(),
        ConnectionRefused | ConnectionAborted | ConnectionReset
    )
}

impl<State> Display for TlsListener<State> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.connection)
    }
}
