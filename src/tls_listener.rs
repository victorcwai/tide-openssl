use crate::{BoxFuture, TcpConnection, TlsListenerBuilder, TlsListenerConfig, TlsStreamWrapper};
use std::fmt::{self, Debug, Display, Formatter};
use tide::listener::{Listener, ToListener};
use tide::Server;

use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::{io, task};

use async_tls::TlsAcceptor;
use rustls::internal::pemfile::{certs, pkcs8_private_keys};
use rustls::{Certificate, NoClientAuth, PrivateKey, ServerConfig};

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug)]
pub struct TlsListener {
    connection: TcpConnection,
    config: TlsListenerConfig,
}

impl TlsListener {
    pub(crate) fn new(connection: TcpConnection, config: TlsListenerConfig) -> Self {
        Self { connection, config }
    }
    pub fn build() -> TlsListenerBuilder {
        TlsListenerBuilder::new()
    }

    async fn configure(&mut self) -> io::Result<TlsAcceptor> {
        self.config = match std::mem::take(&mut self.config) {
            TlsListenerConfig::Paths { cert, key } => {
                let certs = load_certs(&cert)?;
                let mut keys = load_keys(&key)?;
                let mut config = ServerConfig::new(NoClientAuth::new());
                config
                    .set_single_cert(certs, keys.remove(0))
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

                TlsListenerConfig::Acceptor(TlsAcceptor::from(Arc::new(config)))
            }

            TlsListenerConfig::ServerConfig(config) => {
                TlsListenerConfig::Acceptor(TlsAcceptor::from(Arc::new(config)))
            }

            other => other,
        };

        if let TlsListenerConfig::Acceptor(ref a) = self.config {
            Ok(a.clone())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "could not configure tlslistener",
            ))
        }
    }

    async fn connect(&mut self) -> io::Result<&TcpListener> {
        if let TcpConnection::Addrs(addrs) = &self.connection {
            let tcp = TcpListener::bind(&addrs[..]).await?;
            self.connection = TcpConnection::Connected(tcp);
        }

        if let TcpConnection::Connected(tcp) = &self.connection {
            Ok(tcp)
        } else {
            unreachable!()
        }
    }
}

fn handle_tls<State: Send + Sync + 'static>(
    app: Server<State>,
    stream: TcpStream,
    acceptor: TlsAcceptor,
) {
    task::spawn(async move {
        let local_addr = stream.local_addr().ok();
        let peer_addr = stream.peer_addr().ok();

        match acceptor.accept(stream).await {
            Ok(tls_stream) => {
                let stream = TlsStreamWrapper::new(tls_stream);
                let fut = async_h1::accept(stream, |mut req| async {
                    if let Err(_) = req.url_mut().set_scheme("https") {
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

impl<State: Send + Sync + 'static> ToListener<State> for TlsListener {
    type Listener = Self;
    fn to_listener(self) -> io::Result<Self::Listener> {
        Ok(self)
    }
}

impl<State: Send + Sync + 'static> ToListener<State> for TlsListenerBuilder {
    type Listener = TlsListener;
    fn to_listener(self) -> io::Result<Self::Listener> {
        self.build()
    }
}

impl<State: Send + Sync + 'static> Listener<State> for TlsListener {
    fn listen<'a>(&'a mut self, app: Server<State>) -> BoxFuture<'a, async_std::io::Result<()>> {
        Box::pin(async move {
            let acceptor = self.configure().await?;
            let listener = self.connect().await?;
            let mut incoming = listener.incoming();

            while let Some(stream) = incoming.next().await {
                match stream {
                    Err(ref e) if is_transient_error(e) => continue,
                    Err(error) => {
                        let delay = std::time::Duration::from_millis(500);
                        tide::log::error!("Error: {}. Pausing for {:?}.", error, delay);
                        task::sleep(delay).await;
                        continue;
                    }

                    Ok(stream) => {
                        handle_tls(app.clone(), stream, acceptor.clone());
                    }
                };
            }
            Ok(())
        })
    }
}

fn is_transient_error(e: &io::Error) -> bool {
    match e.kind() {
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset => true,
        _ => false,
    }
}

impl Display for TlsListener {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.connection)
    }
}

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
}