//! # Shutdown Signal Utility
//!
//! Provides standard Unix and generic event listners to handle graceful application server termination.

/// Listens for Ctrl+C (SIGINT) or Unix termination (SIGTERM) signals.
///
/// Suspends execution until a termination signal is received, letting the caller trigger
/// a graceful shutdown process for the web application servers.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("initiating graceful shutdown");
        },
        _ = terminate => {
            tracing::info!("initiating graceful shutdown");
        },
    }
}
