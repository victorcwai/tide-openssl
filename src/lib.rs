//! tide tls listener built on async-std-openssl and openssl
//!
//!
//! # Example
//! ```rust
//! # use tide_openssl::TlsListener;
//! # fn main() -> tide::Result<()> { async_std::task::block_on(async {
//!     let mut app = tide::new();
//!     app.at("/").get(|_| async { Ok("Hello tls") });
//! # if false {
//!     app.listen(
//!         TlsListener::build()
//!             .addrs("localhost:4433")
//!             .cert(std::env::var("TIDE_CERT_PATH").unwrap())
//!             .key(std::env::var("TIDE_KEY_PATH").unwrap()),
//!     )
//!    .await?;
//! # } Ok(()) }) }
//! ```
#![forbid(future_incompatible)]
#![forbid(unsafe_code)]
#![deny(
    missing_debug_implementations,
    nonstandard_style,
    missing_docs,
    unreachable_pub,
    missing_copy_implementations,
    unused_qualifications
)]

mod tcp_connection;
mod tls_listener;
mod tls_listener_builder;
mod tls_listener_config;
mod tls_stream_wrapper;

pub(crate) use tcp_connection::TcpConnection;
pub(crate) use tls_listener_config::TlsListenerConfig;

pub use tls_listener::TlsListener;
pub use tls_listener_builder::TlsListenerBuilder;
