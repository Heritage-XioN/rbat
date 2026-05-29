use axum::{Router, routing::get, routing::post};
use axum_standardwebhooks::SharedWebhook;
use color_eyre::Result;
use rbat_server::{
    AppState,
    handlers::{GRPCservice, webhook::receive_webhook},
    transfer::analysis_server::AnalysisServer,
    utils::{log_time::LocalTimeWithoutMillis, minio_client::setup_minio_client},
};
use standardwebhooks::Webhook;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    dotenvy::dotenv().ok(); // Ignore error if .env doesn't exist

    // Initialize structured logging with custom timer (no milliseconds)
    tracing_subscriber::fmt()
        .with_timer(LocalTimeWithoutMillis)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let secret = std::env::var("WEBHOOK_SECRET").unwrap_or_else(|_| {
        tracing::warn!(
            key = "WEBHOOK_SECRET",
            "Environment variable not set. Falling back to default development key."
        );
        "whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD".to_string()
    });

    let state = AppState {
        s3_client: setup_minio_client().await?,
        webhook: SharedWebhook::new(Webhook::new(&secret)?),
    };

    let http_router = Router::new()
        .route("/", get(|| async { "RBAT-Deamon: running" }))
        .route("/health", get(|| async { "HTTP Health Check: OK" }))
        .route("/webhooks", post(receive_webhook))
        .with_state(state.clone());

    let rpc = GRPCservice {
        state: state.clone(),
    };
    let grpc_service = AnalysisServer::new(rpc);

    // Tonic Routes container with service
    let tonic_router = tonic::service::Routes::new(grpc_service).into_axum_router();

    // Merge the routers
    let app = http_router.merge(tonic_router);

    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("{}:{}", host, port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!(address = %addr, "Server running multi-protocol");
    axum::serve(listener, app).await?;

    Ok(())
}
