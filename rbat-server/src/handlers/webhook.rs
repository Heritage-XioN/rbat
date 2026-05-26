use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum_macros::debug_handler;
use axum_standardwebhooks::StandardWebhook;
use serde_json::Value;

use crate::AppState;

#[debug_handler]
pub async fn receive_webhook(
    State(state): State<AppState>,
    StandardWebhook(Json(payload)): StandardWebhook<Json<Value>>,
) -> impl IntoResponse {
    println!("Webhook signature successfully verified!");

    // Spawn the processing to a background task so we can reply immediately
    tokio::spawn(async move {
        //process_webhook_data_in_background(payload).await;
    });

    // Instantly return 200 OK to the sender
    (StatusCode::OK, "OK")
}
