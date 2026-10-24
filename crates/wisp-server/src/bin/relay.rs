use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use wisp_server::{router, Hub, Relay, RelayConfig, Store};
const SWEEP_INTERVAL: Duration = Duration::from_secs(3600);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db_path = std::env::var("WISP_DB").unwrap_or_else(|_| "wisp.db".to_string());
    let bind = bind_address()?;

    let client_ip_header = client_ip_header()?;
    let defaults = RelayConfig::default();
    let config = RelayConfig {
        signups_per_address: env_number("WISP_SIGNUPS_PER_ADDRESS", defaults.signups_per_address)?,
        signups_global: env_number("WISP_SIGNUPS_GLOBAL", defaults.signups_global)?,
        signup_window_secs: env_number("WISP_SIGNUP_WINDOW_SECS", defaults.signup_window_secs)?,
        max_pending_per_recipient: env_number("WISP_MAX_PENDING", defaults.max_pending_per_recipient)?,
        max_envelope_bytes: env_number("WISP_MAX_ENVELOPE_BYTES", defaults.max_envelope_bytes)?,
        ..defaults
    };

    if !bind.ip().is_loopback() && client_ip_header.is_none() {
        eprintln!(
            "[wisp] WARNING: listening on {bind} with no WISP_CLIENT_IP_HEADER or \
             WISP_TRUST_PROXY. If this sits behind a reverse proxy, every visitor will share one \
             rate-limit bucket. If it is exposed directly, traffic is not encrypted (TLS is the \
             proxy's job)."
        );
    }

    let store = Store::open(&db_path)?;
    let hub = Arc::new(Hub::new(Relay::new(store, config)).with_client_ip_header(client_ip_header.clone()));
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
    eprintln!(
        "[wisp] registration is OPEN; client address taken from: {}",
        client_ip_header.as_deref().unwrap_or("the socket")
    );

    axum::serve(
        listener,
        router(hub).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    eprintln!("[wisp] relay stopped");
    Ok(())
}

fn bind_address() -> Result<SocketAddr, Box<dyn std::error::Error>> {
    if let Ok(explicit) = std::env::var("WISP_BIND") {
        return Ok(explicit.trim().parse()?);
    }
    if let Ok(port) = std::env::var("PORT") {
        return Ok(format!("0.0.0.0:{}", port.trim()).parse()?);
    }
    Ok("127.0.0.1:8080".parse()?)
}

fn client_ip_header() -> Result<Option<String>, Box<dyn std::error::Error>> {
    if let Ok(name) = std::env::var("WISP_CLIENT_IP_HEADER") {
        let name = name.trim().to_ascii_lowercase();
        if !name.is_empty() {
            axum::http::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| format!("WISP_CLIENT_IP_HEADER {name:?} is not a valid header name"))?;
            return Ok(Some(name));
        }
    }
    Ok(env_flag("WISP_TRUST_PROXY").then(|| "x-forwarded-for".to_string()))
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            eprintln!("[wisp] shutting down");
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("[wisp] shutting down");
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn env_number<T: std::str::FromStr>(
    name: &str,
    default: T,
) -> Result<T, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(raw) => raw
            .trim()
            .parse()
            .map_err(|_| format!("{name} must be a number, got {raw:?}").into()),
        Err(_) => Ok(default),
    }
}
