use crate::Result;
use aws_sdk_s3::Client as S3Client;
use rbat::core::{AnalysisResult, RiskAssessment, analyzer::analyze_batch};
use std::path::PathBuf;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

pub async fn analyze_stored_binary(
    s3_client: &S3Client,
    file_id: &str,
) -> Result<(AnalysisResult, RiskAssessment)> {
    let bucket = "pt-compromised-binaries";

    // secure, non-executable RAM disk path
    let sandbox_path = PathBuf::from(format!("/tmp/sandbox/{}", file_id));

    let mut download_output = s3_client
        .get_object()
        .bucket(bucket)
        .key(file_id)
        .send()
        .await?;

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&sandbox_path)
        .await?;

    while let Some(chunk) = download_output.body.next().await {
        let bytes = chunk?;
        file.write_all(&bytes).await?;
    }
    file.flush().await?;
    drop(file); // Ensure file handle is closed before analysis

    let path_clone = sandbox_path.clone();
    let results = tokio::task::spawn_blocking(move || analyze_batch(&path_clone)).await??;

    // Force immediate cleanup from the RAM disk
    if let Err(e) = tokio::fs::remove_file(&sandbox_path).await {
        eprintln!("Warning: Failed to delete binary from RAM sandbox: {}", e);
    }

    // drop minio copy
    let _ = s3_client
        .delete_object()
        .bucket(bucket)
        .key(file_id)
        .send()
        .await;

    Ok(results)
}
