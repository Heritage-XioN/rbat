use axum::{Router, routing::get};
use color_eyre::Result;
use rbat_server::{
    AppState, handlers::GRPCservice, transfer::analysis_server::AnalysisServer,
    utils::minio_client::setup_minio_client,
};
use std::sync::Arc;
use tui_banner::Banner;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let state = Arc::new(AppState {
        s3_client: setup_minio_client().await?,
    });

    // Generate and display banner
    let font =
        tui_banner::Font::from_figlet_str(include_str!("../.././rbat-core/assets/ansishadow.flf"))
            .map_err(|e| color_eyre::eyre::eyre!("Failed to parse ANSI Shadow font: {:?}", e))?;
    let banner = Banner::new("RBAT-SERVER")?
        .font(font)
        .gradient(tui_banner::Gradient::vertical(
            tui_banner::Palette::from_hex(&[
                "#FDBA74", // Peach/light orange
                "#F97316", // Orange
                "#9A3412", // Rust
                "#431407", // Dark brown/red
            ]),
        ))
        .fill(tui_banner::Fill::Keep)
        .render();
    println!("\n {}", banner);

    let http_router = Router::new()
        .route("/", get(|| async { "RBAT-Deamon: running" }))
        .route("/health", get(|| async { "HTTP Health Check: OK" }))
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

    println!("Server running multi-protocol on http://{}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}
