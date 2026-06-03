//! # HTTP Webhooks Router Handler
//!
//! Exposes HTTP endpoints allowing external clients or background proxies to verify
//! and dispatch analytical operations via secure standard webhooks signing schemes.

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

/// Expected structure of the incoming webhook payload body.
#[derive(Deserialize)]
pub struct WebhookPayload {
    /// The event classification, e.g. `analysis.start`.
    pub event_type: String,
    /// Inner payload data matching the event category (e.g. metadata or file identifiers).
    pub data: Value,
}

/// Receives, authenticates, and dispatches webhook events.
///
/// Under standard configuration, signature verification is handled implicitly
/// by the `StandardWebhook` extractor using the `WEBHOOK_SECRET` key.
///
/// # Errors
/// Returns a `StatusCode::BAD_REQUEST` if the event is valid but lacks expected fields (like `file_id`),
/// or `StatusCode::INTERNAL_SERVER_ERROR` if the background static analysis initialization fails.
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

    tracing::debug!(
        webhook_timestamp,
        webhook_signature,
        "Webhook signature successfully verified detail"
    );
    tracing::info!("Webhook signature successfully verified");

    match payload.event_type.as_str() {
        "analysis.start" => {
            let file_id = payload.data["file_id"].as_str().ok_or_else(|| {
                tracing::error!("Webhook payload did not contain a valid file_id");
                (
                    StatusCode::BAD_REQUEST,
                    "Missing file_id in data payload".to_string(),
                )
            })?;

            analyze_stored_binary(
                state.s3_client.clone(),
                file_id.to_string(),
                state.webhook_secret.clone(),
            );
        }
        _ => {
            tracing::warn!(event_type = %payload.event_type, "Received unknown event type");
        }
    }

    // Instantly return 200 OK to the sender
    Ok((StatusCode::OK, "OK"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_webhook_payload_deserialization() {
        let valid_json = json!({
            "event_type": "analysis.start",
            "data": {
                "file_id": "936da01f-9abd-4d9d-80c7-02af85c822a8"
            }
        });

        let payload: WebhookPayload = serde_json::from_value(valid_json).unwrap();
        assert_eq!(payload.event_type, "analysis.start");
        assert_eq!(
            payload.data["file_id"].as_str().unwrap(),
            "936da01f-9abd-4d9d-80c7-02af85c822a8"
        );

        let invalid_json = json!({
            "data": {}
        });
        let result: Result<WebhookPayload, _> = serde_json::from_value(invalid_json);
        assert!(result.is_err());
    }
}
