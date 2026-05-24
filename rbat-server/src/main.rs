use axum::{Router, routing::get};
use rbat_server::{handlers::GRPCservice, transfer::analysis_server::AnalysisServer};


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let http_router = Router::new()
        .route("/", get(|| async { "RBAT-Deamon: running" }))
        .route("/health", get(|| async { "HTTP Health Check: OK" }));
    let grpc_service = AnalysisServer::new(GRPCservice::default());

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
