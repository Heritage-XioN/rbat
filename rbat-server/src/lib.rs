pub mod handlers;
pub mod services;
pub mod utils;

pub mod transfer {
    tonic::include_proto!("transfer");
}
use std::fmt::Debug;

use aws_sdk_s3::Client as S3Client;
use axum::extract::FromRef;
use axum_standardwebhooks::SharedWebhook;
use thiserror::Error;

/// Represents all possible error conditions returned by the RBAT server library.
#[derive(Debug, Error)]
pub enum RbatServerError {
    /// Standard input/output operations error.
    #[error("I/O error occurred")]
    Io(#[from] std::io::Error),

    #[error("error analyzing binary")]
    Rbat(#[from] rbat::core::error::RbatError),

    #[error("AWS sdk error occurred: {0}")]
    S3client(String),

    #[error("Byte stream error occurred: {0}")]
    ByteStream(#[from] aws_sdk_s3::primitives::ByteStreamError),

    #[error("Task join error occurred: {0}")]
    Join(#[from] tokio::task::JoinError),

    #[error("Environment variable error: {0}")]
    EnvVar(#[from] std::env::VarError),

    #[error("JSON serialization/deserialization error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("Standard Webhooks error: {0}")]
    StandardWebhooks(#[from] standardwebhooks::WebhookError),

    #[error("HTTP client error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("Internal server error: {0}")]
    Internal(String),
}

impl<E, R> From<aws_sdk_s3::error::SdkError<E, R>> for RbatServerError
where
    E: std::fmt::Debug + std::error::Error + 'static,
    R: std::fmt::Debug + 'static,
{
    fn from(err: aws_sdk_s3::error::SdkError<E, R>) -> Self {
        RbatServerError::S3client(err.to_string())
    }
}

pub type Result<T> = core::result::Result<T, RbatServerError>;

#[derive(Clone)]
pub struct AppState {
    pub s3_client: S3Client,
    pub webhook: SharedWebhook,
}

impl FromRef<AppState> for SharedWebhook {
    fn from_ref(state: &AppState) -> Self {
        state.webhook.clone()
    }
}
