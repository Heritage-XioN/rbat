pub mod handlers;
pub mod utils;
pub mod transfer {
    tonic::include_proto!("transfer");
}
use aws_sdk_s3::Client as S3Client;
use thiserror::Error;

/// Represents all possible error conditions returned by the RBAT server library.
#[derive(Debug, Error)]
pub enum RbatServerError {
    /// Standard input/output operations error.
    #[error("I/O error occurred")]
    Io(#[from] std::io::Error),
    // #[error("rpc status")]
    // Rpc(#[from] tonic::Status),
}
pub type Result<T> = core::result::Result<T, RbatServerError>;

#[derive(Debug, Clone)]
pub struct AppState {
    pub s3_client: S3Client,
}
