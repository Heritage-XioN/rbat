//! # Binary Analysis Service
//!
//! Handles fetching, analyzing, and reporting on stored binary targets asynchronously.
//! Once called, it retrieves the binary file buffer from the object store, delegates the static
//! processing pipeline to heavy-CPU Rayon worker threads, and sends the completion status
//! payload to the client via Webhook dispatch.

use crate::utils::webhook_sender::dispatch_webhook;
use rbat::core::analyzer::analyze_batch;
use s3::Bucket as S3Client;
use serde_json::{json, to_value};
use tokio::sync::oneshot;
use tracing::Instrument;

/// Pulls a binary from the object store and triggers background static analysis.
///
/// Analysis calculations are executed on a Rayon CPU-bound worker thread, ensuring the async network
/// loop remains unblocked. When completed, findings are dispatched via webhook to the client callback,
/// and the temporary binary file is deleted from object storage.
///
/// # Errors
/// Returns an error if the S3 client fails to pull the object, or if we cannot delete the S3 object
/// after analysis (though the background thread still completes analysis on failure to delete).
#[tracing::instrument(skip(s3_client))]
pub fn analyze_stored_binary(s3_client: S3Client, file_id: String, webhook_secret: String) {
    let file_id_clone = file_id.clone();
    let span = tracing::info_span!("analyze_stored_binary_background", file_id = %file_id_clone);
    tokio::spawn(
        async move {
            let bucket = "pt-compromised-binaries";

            tracing::debug!(
                bucket,
                key = %file_id,
                "Downloading binary from S3"
            );

            let download_output = match s3_client.get_object(&file_id).await {
                Ok(output) => output,
                Err(e) => {
                    tracing::error!(bucket, key = %file_id, error = ?e, "Failed to get object from S3");
                    return;
                }
            };

            let payload = download_output.bytes().to_vec();

            let webhook_url = match std::env::var("WEBHOOK_TARGET_URL") {
                Ok(url) => url,
                Err(_) => {
                    tracing::warn!(
                        var = "WEBHOOK_TARGET_URL",
                        "Environment variable not set. Skipping webhook dispatch"
                    );
                    return;
                }
            };
            let event_id = uuid::Uuid::new_v4().to_string();

            // Bridge to safely get the struct back from Rayon
            let (tx, rx) = oneshot::channel();

            // Offload to Rayon's CPU threads
            rayon::spawn(move || {
                let result = analyze_batch(&payload);
                let _ = tx.send(result);
            });

            if let Ok(analysis_result) = rx.await {
                match analysis_result {
                    Ok(report) => {
                        let analysis_result = match to_value(report.0) {
                            Ok(val) => val,
                            Err(e) => {
                                tracing::error!(error = ?e, "Failed to serialize analysis result");
                                return;
                            }
                        };
                        let risk_assesment = match to_value(report.1) {
                            Ok(val) => val,
                            Err(e) => {
                                tracing::error!(error = ?e, "Failed to serialize risk assessment");
                                return;
                            }
                        };
                        let report_json = json!({
                            "event_type": "analysis.completed",
                            "data": {
                                "file_id": file_id_clone,
                                "analysis_result": analysis_result,
                                "risk_assesment": risk_assesment
                            }
                        });

                        dispatch_webhook(webhook_url, event_id, report_json, webhook_secret.clone()).await;
                    }
                    Err(e) => {
                        // Handle malformed binary or processing error
                        let report_json = json!({
                            "event_type": "analysis.failed",
                            "data": {
                                "file_id": file_id_clone,
                                "error": e
                            }
                        });
                        tracing::error!(error = ?e, "Analysis failed for binary");
                        dispatch_webhook(webhook_url, event_id, report_json, webhook_secret.clone()).await;
                    }
                }
            }

            // drop minio copy
            if let Err(e) = s3_client.delete_object(&file_id).await {
                tracing::error!(bucket, key = %file_id, error = ?e, "Failed to delete binary from MinIO");
            } else {
                tracing::info!(bucket, key = %file_id, "Successfully deleted temporary binary from MinIO");
            }
        }
        .instrument(span),
    );
}
