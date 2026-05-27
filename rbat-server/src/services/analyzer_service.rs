use crate::Result;
use crate::utils::webhook_sender::dispatch_webhook;
use aws_sdk_s3::Client as S3Client;
use rbat::core::analyzer::analyze_batch;
use serde_json::{json, to_value};
use tokio::sync::oneshot;
use tracing::Instrument;

#[tracing::instrument(skip(s3_client))]
pub async fn analyze_stored_binary(s3_client: &S3Client, file_id: &str) -> Result<&'static str> {
    let bucket = "pt-compromised-binaries";

    tracing::debug!(
        bucket,
        key = %file_id,
        "Downloading binary from S3"
    );

    let mut download_output = s3_client
        .get_object()
        .bucket(bucket)
        .key(file_id)
        .send()
        .await
        .map_err(|e| {
            crate::RbatServerError::S3client(format!("Failed to get object from S3: {}", e))
        })?;

    let mut payload = Vec::new();
    while let Some(chunk) = download_output.body.next().await {
        let bytes = chunk.map_err(|e| crate::RbatServerError::ByteStream(e))?;
        payload.extend_from_slice(&bytes);
    }

    let file_id_clone = file_id.to_string();
    let span = tracing::info_span!("analyze_stored_binary_background", file_id = %file_id_clone);
    tokio::spawn(
        async move {
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

                        dispatch_webhook(webhook_url, event_id, report_json).await;
                    }
                    Err(e) => {
                        // Handle malformed binary or processing error
                        tracing::error!(error = ?e, "Analysis failed for binary");
                    }
                }
            }
        }
        .instrument(span),
    );

    // drop minio copy
    if let Err(e) = s3_client
        .delete_object()
        .bucket(bucket)
        .key(file_id)
        .send()
        .await
    {
        tracing::error!(bucket, key = %file_id, error = ?e, "Failed to delete binary from MinIO");
    } else {
        tracing::info!(bucket, key = %file_id, "Successfully deleted binary copy from MinIO");
    }

    Ok("ok")
}
