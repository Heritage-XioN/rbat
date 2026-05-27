use crate::Result;
use aws_config::BehaviorVersion;
use aws_sdk_s3::{Client as S3Client, config::Credentials};

pub async fn setup_minio_client() -> Result<S3Client> {
    let root_user = std::env::var("MINIO_ROOT_USER").unwrap_or_else(|_| {
        tracing::warn!(
            var = "MINIO_ROOT_USER",
            "Environment variable not set. Using development default"
        );
        "admin_user".to_string()
    });
    let root_password = std::env::var("MINIO_ROOT_PASSWORD").unwrap_or_else(|_| {
        tracing::warn!(
            var = "MINIO_ROOT_PASSWORD",
            "Environment variable not set. Using development default"
        );
        "super_secure_password_123".to_string()
    });
    let endpoint = std::env::var("MINIO_ENDPOINT").unwrap_or_else(|_| {
        tracing::info!(
            var = "MINIO_ENDPOINT",
            default = "http://localhost:9000",
            "Environment variable not set. Using development default"
        );
        "http://localhost:9000".to_string()
    });

    let credentials = Credentials::new(root_user, root_password, None, None, "Static");

    let config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(credentials)
        .region(aws_config::Region::new("us-east-1")) // Dummy region required by SDK
        .load()
        .await;

    // Force the client to point to your local container endpoint
    let s3_config = aws_sdk_s3::config::Builder::from(&config)
        .endpoint_url(endpoint)
        .force_path_style(true) // Required for MinIO compatibility
        .build();

    Ok(S3Client::from_conf(s3_config))
}
