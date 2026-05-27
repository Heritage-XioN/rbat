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
#[tracing::instrument(
    skip(state, headers, payload),
    fields(
        webhook_id = tracing::field::Empty,
        delivery_id = tracing::field::Empty,
        event_type = tracing::field::Empty,
    )
)]
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

    let span = tracing::Span::current();
    span.record("webhook_id", webhook_id);
    span.record("delivery_id", delivery_id);
    span.record("event_type", event_type);

    tracing::info!(
        webhook_timestamp,
        webhook_signature,
        "Webhook signature successfully verified"
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
                    tracing::error!(file_id = %file_id, error = ?e, "Failed to analyze stored binary");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Analysis failed: {}", e),
                    )
                })?;
        }
        _ => {
            tracing::warn!(event_type = %payload.event_type, "Received unknown event type");
        }
    }

    // Instantly return 200 OK to the sender
    Ok((StatusCode::OK, "OK"))
}
