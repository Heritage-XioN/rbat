use crate::{RbatServerError, Result};
use s3::Bucket as S3Client;
use s3::creds::Credentials;
use s3::{BucketConfiguration, Region};

pub async fn setup_minio_client() -> Result<S3Client> {
    let root_user = std::env::var("MINIO_ROOT_USER").unwrap_or_else(|_| {
        tracing::warn!(
            var = "MINIO_ROOT_USER",
            "Environment variable not set. Using development default"
        );
        "admin".to_string()
    });
    let root_password = std::env::var("MINIO_ROOT_PASSWORD").unwrap_or_else(|_| {
        tracing::warn!(
            var = "MINIO_ROOT_PASSWORD",
            "Environment variable not set. Using development default"
        );
        "password123".to_string()
    });
    let endpoint = std::env::var("MINIO_ENDPOINT").unwrap_or_else(|_| {
        tracing::info!(
            var = "MINIO_ENDPOINT",
            default = "http://localhost:9000",
            "Environment variable not set. Using development default"
        );
        "http://localhost:9000".to_string()
    });

    let credentials = Credentials::new(Some(&root_user), Some(&root_password), None, None, None)
        .map_err(|e| RbatServerError::S3client(e.to_string()))?;

    let region = Region::Custom {
        region: "us-east-1".to_string(),
        endpoint: endpoint.clone(),
    };

    let bucket_name = "pt-compromised-binaries";
    let mut bucket = S3Client::new(bucket_name, region.clone(), credentials.clone())
        .map_err(|e| RbatServerError::S3client(e.to_string()))?;
    bucket.set_path_style();

    // Check if the bucket exists. If not, create it.
    let exists = bucket.exists().await.unwrap_or(false);
    if !exists {
        tracing::info!(
            bucket = bucket_name,
            "Bucket does not exist. Creating it..."
        );
        S3Client::create_with_path_style(
            bucket_name,
            region,
            credentials,
            BucketConfiguration::default(),
        )
        .await
        .map_err(|e| RbatServerError::S3client(e.to_string()))?;
        tracing::info!(bucket = bucket_name, "Bucket created successfully.");
    } else {
        tracing::info!(bucket = bucket_name, "Bucket already exists.");
    }

    Ok(bucket)
}
