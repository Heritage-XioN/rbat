//! # MinIO Storage Client Setup
//!
//! Provides helper functions to connect to, verify, and initialize a target S3 bucket in MinIO.

use crate::{RbatServerError, Result};
use s3::Bucket as S3Client;
use s3::creds::Credentials;
use s3::{BucketConfiguration, Region};

/// Initializes the MinIO / S3 storage bucket and client wrapper.
///
/// Verifies credentials and checks if the bucket `pt-compromised-binaries` exists.
/// If not, it attempts to create it with path-style access.
///
/// # Errors
/// Returns `RbatServerError::Internal` in production mode if either `MINIO_ROOT_USER` or `MINIO_ROOT_PASSWORD`
/// is missing from the environment variables, or `RbatServerError::S3client` if connection / creation fails.
pub async fn setup_minio_client() -> Result<S3Client> {
    let is_prod = std::env::var("RUN_MODE").unwrap_or_default() == "production";

    let root_user = match std::env::var("MINIO_ROOT_USER") {
        Ok(val) => val,
        Err(_) => {
            if is_prod {
                return Err(RbatServerError::Internal(
                    "MINIO_ROOT_USER environment variable is missing in production!".to_string(),
                ));
            }
            tracing::warn!(
                var = "MINIO_ROOT_USER",
                "Environment variable not set. Using development default"
            );
            "admin".to_string()
        }
    };

    let root_password = match std::env::var("MINIO_ROOT_PASSWORD") {
        Ok(val) => val,
        Err(_) => {
            if is_prod {
                return Err(RbatServerError::Internal(
                    "MINIO_ROOT_PASSWORD environment variable is missing in production!"
                        .to_string(),
                ));
            }
            tracing::warn!(
                var = "MINIO_ROOT_PASSWORD",
                "Environment variable not set. Using development default"
            );
            "password123".to_string()
        }
    };
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
    let exists = bucket.exists().await.map_err(|e| RbatServerError::S3client(e.to_string()))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Mutex;

    // Use global mutex to prevent race conditions during env changes in parallel tests
    static ENV_MUTEX: Mutex<()> = Mutex::const_new(());

    #[tokio::test]
    async fn test_setup_minio_client_prod_missing_vars() {
        let _guard = ENV_MUTEX.lock().await;

        // Backup existing env vars
        let backup_run_mode = std::env::var("RUN_MODE").ok();
        let backup_root_user = std::env::var("MINIO_ROOT_USER").ok();
        let backup_root_password = std::env::var("MINIO_ROOT_PASSWORD").ok();

        // Set env to mimic production with missing credentials
        unsafe {
            std::env::set_var("RUN_MODE", "production");
            std::env::remove_var("MINIO_ROOT_USER");
            std::env::remove_var("MINIO_ROOT_PASSWORD");
        }

        let result = setup_minio_client().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RbatServerError::Internal(_)));

        // Restore env vars
        unsafe {
            if let Some(val) = backup_run_mode {
                std::env::set_var("RUN_MODE", val);
            } else {
                std::env::remove_var("RUN_MODE");
            }
            if let Some(val) = backup_root_user {
                std::env::set_var("MINIO_ROOT_USER", val);
            } else {
                std::env::remove_var("MINIO_ROOT_USER");
            }
            if let Some(val) = backup_root_password {
                std::env::set_var("MINIO_ROOT_PASSWORD", val);
            } else {
                std::env::remove_var("MINIO_ROOT_PASSWORD");
            }
        }
    }
}
