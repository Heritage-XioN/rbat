//! # HTTP Webhook Sender Utility
//!
//! Spawns background tasks to sign and send event webhooks asynchronously to external target receivers.

use std::sync::OnceLock;

use chrono::Utc;
use reqwest::Client;
use serde_json::Value;
use standardwebhooks::Webhook;
use tokio_retry::RetryIf;
use tokio_retry::strategy::{ExponentialBackoff, jitter};
use tracing::Instrument;

static HTTP_CLIENT: OnceLock<Client> = OnceLock::new();

/// Dispatches an event webhook payload to a target URL in a background task.
///
/// Under the hood:
/// - Spawns a background `tokio` thread.
/// - signs the event payload using standard webhook headers (e.g. `webhook-signature`).
/// - Executes the request inside a retry loop with exponential backoff (up to 5 retries, jittered).
/// - Filters retry triggers: only retries on network failures or 5xx server errors, not on 4xx statuses.
pub async fn dispatch_webhook(target_url: String, event_id: String, payload: Value, secret: String) {
    let span =
        tracing::info_span!("dispatch_webhook", event_id = %event_id, target_url = %target_url);
    // Spawn the work to a background task so it doesn't block the caller thread
    tokio::spawn(async move {
        let client = HTTP_CLIENT.get_or_init(Client::new);
        let payload_str = payload.to_string();
        let timestamp = Utc::now().timestamp();

        // Extract event_type for custom header setting
        let event_type = payload
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        // Generate the Standard Webhook signature
        let wh = match Webhook::new(&secret) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!(error = ?e, "Failed to initialize webhook signer");
                return;
            }
        };

        let signature = match wh.sign(&event_id, timestamp, payload_str.as_bytes()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = ?e, "Failed to sign webhook payload");
                return;
            }
        };

        // retry strategy: 5 retries, starting at 1 second, doubling each time (1s, 2s, 4s, 8s, 16s)
        let retry_strategy = ExponentialBackoff::from_millis(1000)
            .factor(2)
            .map(jitter)
            .take(5);

        // Execute the request loop
        let result = RetryIf::spawn(
            retry_strategy,
            || {
                let client = client.clone();
                let url = target_url.clone();
                let body = payload_str.clone();
                let id = event_id.clone();
                let ts = timestamp;
                let sig = signature.clone();
                let ev_type = event_type.clone();

                async move {
                    tracing::debug!("Attempting to send webhook");

                    client
                        .post(&url)
                        .header("webhook-id", id.clone())
                        .header("webhook-timestamp", ts.to_string())
                        .header("webhook-signature", sig)
                        .header("event-type", ev_type)
                        .header("delivery-id", id)
                        .header("content-type", "application/json")
                        .body(body)
                        .send()
                        .await
                        .and_then(|res| res.error_for_status())
                }
            },
            |error: &reqwest::Error| {
                // Condition to retry: Only retry on network failures or server errors (5xx).
                // Do NOT retry if the consumer returned a 400 Bad Request or 401 Unauthorized,
                // as retrying won't fix bad authentication or payload issues.
                if let Some(status) = error.status() {
                    status.is_server_error() // Retries on 500, 502, 503, 504
                } else {
                    true // Retries on network timeouts, DNS errors, connection dropped
                }
            },
        )
        .await;

        match result {
            Ok(response) => {
                tracing::info!(
                    status = %response.status(),
                    "Webhook successfully delivered"
                );
            }
            Err(e) => {
                if let Some(status) = e.status() {
                    if status.is_client_error() {
                        tracing::debug!(
                            status = %status,
                            "Webhook gave up; consumer returned client error status"
                        );
                        return;
                    }
                }
                tracing::debug!(
                    error = ?e,
                    "Webhook delivery completely failed after maximum retries"
                );
            }
        }
    }.instrument(span));
}
