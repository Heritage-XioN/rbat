use crate::Result;
use aws_config::BehaviorVersion;
use aws_sdk_s3::{Client as S3Client, config::Credentials};

pub async fn setup_minio_client() -> Result<S3Client> {
    let credentials = Credentials::new(
        "admin_user",                // Your MINIO_ROOT_USER
        "super_secure_password_123", // Your MINIO_ROOT_PASSWORD
        None,
        None,
        "Static",
    );

    let config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(credentials)
        .region(aws_config::Region::new("us-east-1")) // Dummy region required by SDK
        .load()
        .await;

    // Force the client to point to your local container endpoint
    let s3_config = aws_sdk_s3::config::Builder::from(&config)
        .endpoint_url("http://localhost:9000")
        .force_path_style(true) // Required for MinIO compatibility
        .build();

    Ok(S3Client::from_conf(s3_config))
}
