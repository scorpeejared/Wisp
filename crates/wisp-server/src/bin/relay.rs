//! The Wisp relay daemon.
//!
//! ```text
//! WISP_DB=/var/lib/wisp/wisp.db WISP_BIND=0.0.0.0:8443 wisp-relay
//! ```
//!
//! TLS is deliberately not handled here. The relay expects to sit behind a
//! terminating proxy (Caddy or nginx with Let's Encrypt), which is both less
//! code in the security-critical path and the arrangement the deployment target
//! already assumes. Note that behind a proxy the throttling scope needs a
//! trusted forwarded-header reading — see `ClientScope` in `routes.rs`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use wisp_server::{router, Hub, Relay, RelayConfig, Store};

const SWEEP_INTERVAL: Duration = Duration::from_secs(3600);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db_path = std::env::var("WISP_DB").unwrap_or_else(|_| "wisp.db".to_string());
    let bind: SocketAddr = std::env::var("WISP_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()?;

    let store = Store::open(&db_path)?;
    let hub = Arc::new(Hub::new(Relay::new(store, RelayConfig::default())));

    // Undelivered messages for someone who never reconnects must not pile up
    // forever; the relay is meant to forget.
    let sweeper = Arc::clone(&hub);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            ticker.tick().await;
            match sweeper.relay.sweep() {
                Ok(0) => {}
                Ok(n) => eprintln!("[wisp] expired {n} undelivered message(s)"),
                Err(e) => eprintln!("[wisp] sweep failed: {e}"),
            }
        }
    });

    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!("[wisp] relay listening on {bind}, database {db_path}");

    // ConnectInfo is what the throttling scope is derived from.
    axum::serve(
        listener,
        router(hub).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    eprintln!("[wisp] relay stopped");
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("[wisp] shutting down");
}
