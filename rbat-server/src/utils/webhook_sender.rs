use std::env;

use chrono::Utc;
use reqwest::Client;
use serde_json::Value;
use standardwebhooks::Webhook;
use tokio_retry::RetryIf;
use tokio_retry::strategy::{ExponentialBackoff, jitter};
use tracing::Instrument;

pub async fn dispatch_webhook(target_url: String, event_id: String, payload: Value) {
    let span =
        tracing::info_span!("dispatch_webhook", event_id = %event_id, target_url = %target_url);
    // Spawn the work to a background task so it doesn't block the caller thread
    tokio::spawn(async move {
        let client = Client::new();
        let payload_str = payload.to_string();
        let timestamp = Utc::now().timestamp();
        let secret = env::var("WEBHOOK_SECRET").unwrap_or_else(|_| {
            let is_prod = env::var("RUN_MODE").unwrap_or_default() == "production";
            if is_prod {
                panic!("CRITICAL CONFIG ERROR: WEBHOOK_SECRET environment variable is missing in production background task!");
            }
            tracing::debug!("WEBHOOK_SECRET environment variable not set. Falling back to default development key.");
            "whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD".to_string()
        });

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
                if response.status().is_success() {
                    tracing::info!(
                        status = %response.status(),
                        "Webhook successfully delivered"
                    );
                } else {
                    tracing::error!(
                        status = %response.status(),
                        "Webhook gave up; consumer returned client error status"
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    error = ?e,
                    "Webhook delivery completely failed after maximum retries"
                );
            }
        }
    }.instrument(span));
}
