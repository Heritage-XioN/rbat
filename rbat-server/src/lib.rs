use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tonic::{Request, Response, Status, Streaming};

pub mod transfer {
    tonic::include_proto!("transfer");
}
use transfer::analysis_server::Analysis;
use transfer::{UploadRequest, UploadResponse};

#[derive(Default)]
pub struct RbatServer;

#[tonic::async_trait]
impl Analysis for RbatServer {
    async fn upload_binary(
        &self,
        request: Request<Streaming<UploadRequest>>,
    ) -> Result<Response<UploadResponse>, Status> {
        let mut stream = request.into_inner();
        let mut file: Option<File> = None;
        let mut total_bytes = 0;

        while let Some(req) = stream.message().await? {
            if file.is_none() {
                // Creates a file in the local directory named after what the client sent
                let safe_name = format!("server_received_{}", req.filename);
                file = Some(File::create(&safe_name).await.map_err(|e| {
                    Status::internal(format!("Failed to create destination file: {e}"))
                })?);
            }

            if let Some(ref mut f) = file {
                f.write_all(&req.chunk_data)
                    .await
                    .map_err(|e| Status::internal(format!("Write pipeline failure: {e}")))?;
                total_bytes += req.chunk_data.len() as u64;
            }
        }

        println!("Successfully saved upload. Total bytes: {}", total_bytes);

        Ok(Response::new(UploadResponse {
            file_id: "generated-uuid-string".to_string(),
            total_bytes_received: total_bytes,
        }))
    }
}
