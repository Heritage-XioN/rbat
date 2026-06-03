//! # RBAT Server
//!
//! `rbat-server` is the backend daemon for the Rust Binary Analysis Tool (RBAT).
//! It provides high-performance services to support static binary analysis:
//! - **gRPC Streaming upload**: Serves the Tonic gRPC service defined in `transfer.proto` to upload large files in chunks.
//! - **HTTP Webhook Receiver**: Implements Axum routes to receive and verify webhooks (e.g. `analysis.start`) from the client frontend.
//! - **MinIO / S3 Storage Integration**: Manages the local upload and storage of binaries using AWS S3-compatible APIs.
//! - **Background Heuristic processing**: Triggers binary analysis routines offloaded asynchronously to Rayon worker threads.

pub mod handlers;
pub mod services;
pub mod utils;

/// Protobuf-generated service and message definitions for binary transfer.
pub mod transfer {
    tonic::include_proto!("transfer");
}
use std::fmt::Debug;

use axum::extract::FromRef;
use axum_standardwebhooks::SharedWebhook;
use s3::Bucket as S3Client;
use thiserror::Error;

/// Represents all possible error conditions returned by the RBAT server library.
#[derive(Debug, Error)]
pub enum RbatServerError {
    /// Standard input/output operations error.
    #[error("I/O error occurred")]
    Io(#[from] std::io::Error),

    /// Error returned by the core analysis engine.
    #[error("error analyzing binary")]
    Rbat(#[from] rbat::core::error::RbatError),

    /// Errors originating from the S3 / MinIO storage client interface.
    #[error("AWS sdk error occurred: {0}")]
    S3client(String),

    /// Error during processing of a byte stream payload.
    #[error("Byte stream error occurred: {0}")]
    ByteStream(String),

    /// Error resulting from task spawning or thread join failures.
    #[error("Task join error occurred: {0}")]
    Join(#[from] tokio::task::JoinError),

    /// Error reading environment configuration variables.
    #[error("Environment variable error: {0}")]
    EnvVar(#[from] std::env::VarError),

    /// Serialization/deserialization failure with JSON format datasets.
    #[error("JSON serialization/deserialization error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    /// Validation or signature error related to webhooks signing.
    #[error("Standard Webhooks error: {0}")]
    StandardWebhooks(#[from] standardwebhooks::WebhookError),

    /// HTTP request dispatch failures (e.g., webhook notifications).
    #[error("HTTP client error: {0}")]
    Reqwest(#[from] reqwest::Error),

    /// Internal error condition representing unrecoverable logical failures.
    #[error("Internal server error: {0}")]
    Internal(String),
}

impl From<s3::error::S3Error> for RbatServerError {
    fn from(err: s3::error::S3Error) -> Self {
        RbatServerError::S3client(err.to_string())
    }
}

/// A specialized Result type alias for RBAT server operations.
pub type Result<T> = core::result::Result<T, RbatServerError>;

/// Represents the shared global application state accessible by HTTP and gRPC service routes.
#[derive(Clone)]
pub struct AppState {
    /// The S3/MinIO client connection bucket.
    pub s3_client: S3Client,
    /// The shared webhook signing and verification structure.
    pub webhook: SharedWebhook,
    /// The webhook secret key used for signing outgoing payloads.
    pub webhook_secret: String,
}

impl FromRef<AppState> for SharedWebhook {
    fn from_ref(state: &AppState) -> Self {
        state.webhook.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use s3::Region;
    use s3::creds::Credentials;
    use standardwebhooks::Webhook;

    #[test]
    fn test_error_conversions() {
        // Test standard IO error conversion
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "test file not found");
        let server_err = RbatServerError::from(io_err);
        assert!(matches!(server_err, RbatServerError::Io(_)));

        // Test S3 error conversion
        let s3_err = s3::error::S3Error::CredentialsReadLock;
        let server_err = RbatServerError::from(s3_err);
        assert!(matches!(server_err, RbatServerError::S3client(_)));
    }

    #[test]
    fn test_app_state_from_ref() {
        let credentials = Credentials::new(Some("user"), Some("pass"), None, None, None).unwrap();
        let region = Region::Custom {
            region: "us-east-1".to_string(),
            endpoint: "http://localhost:9000".to_string(),
        };
        let s3_client = S3Client::new("test-bucket", region, credentials).unwrap();
        let webhook_signer = Webhook::new("whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD").unwrap();
        let webhook = SharedWebhook::new(webhook_signer);

        let state = AppState {
            s3_client,
            webhook,
            webhook_secret: "whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD".to_string(),
        };

        // SharedWebhook should be extractable from AppState via FromRef
        let extracted = SharedWebhook::from_ref(&state);
        // We verify extraction completes successfully
        let headers = axum::http::HeaderMap::new();
        assert!(extracted.clone().verify(b"payload", &headers).is_err());
    }
}
