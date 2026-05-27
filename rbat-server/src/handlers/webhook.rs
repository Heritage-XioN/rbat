use crate::AppState;
use crate::services::analyzer_service::analyze_stored_binary;
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum_macros::debug_handler;
use axum_standardwebhooks::StandardWebhook;
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
pub struct WebhookPayload {
    event_type: String,
    data: Value,
}

#[debug_handler]
pub async fn receive_webhook(
    headers: HeaderMap,
    State(state): State<AppState>,
    StandardWebhook(Json(payload)): StandardWebhook<Json<WebhookPayload>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Extract headers for logging / future database storing
    let webhook_id = headers
        .get("webhook-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let webhook_timestamp = headers
        .get("webhook-timestamp")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let webhook_signature = headers
        .get("webhook-signature")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let event_type = headers
        .get("event-type")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let delivery_id = headers
        .get("delivery-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    tracing::info!(
        "Webhook signature successfully verified! \
         [Headers -> webhook-id: {}, webhook-timestamp: {}, webhook-signature: {}, x-rbat-event: {}, x-delivery-id: {}]",
        webhook_id,
        webhook_timestamp,
        webhook_signature,
        event_type,
        delivery_id
    );

    match payload.event_type.as_str() {
        "analysis.start" => {
            let file_id = payload.data["file_id"].as_str().ok_or_else(|| {
                tracing::error!("Webhook payload did not contain a valid file_id");
                (
                    StatusCode::BAD_REQUEST,
                    "Missing file_id in data payload".to_string(),
                )
            })?;

            analyze_stored_binary(&state.s3_client, file_id)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to analyze stored binary {}: {:?}", file_id, e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Analysis failed: {}", e),
                    )
                })?;
        }
        _ => {
            tracing::warn!("Received unknown event type: {}", payload.event_type);
        }
    }

    // Instantly return 200 OK to the sender
    Ok((StatusCode::OK, "OK"))
}
