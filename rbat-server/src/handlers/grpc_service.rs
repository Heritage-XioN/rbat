use crate::{
    AppState,
    transfer::{UploadRequest, UploadResponse, analysis_server::Analysis},
};

use aws_sdk_s3::types::CompletedMultipartUpload;
use aws_sdk_s3::types::CompletedPart;
use tonic::{Request, Response, Status, Streaming};
use uuid::Uuid;

pub struct GRPCservice {
    pub state: AppState,
}

#[tonic::async_trait]
impl Analysis for GRPCservice {
    #[tracing::instrument(skip(self, request), fields(file_id = tracing::field::Empty))]
    async fn upload_binary(
        &self,
        request: Request<Streaming<UploadRequest>>,
    ) -> Result<Response<UploadResponse>, Status> {
        let mut stream = request.into_inner();
        let s3_client = &self.state.s3_client;
        let bucket = "pt-compromised-binaries";
        let file_id = Uuid::new_v4().to_string();
        tracing::Span::current().record("file_id", &file_id);
        let mut total_bytes = 0;

        // Initiate the Multipart upload in MinIO
        let create_multipart_upload_output = s3_client
            .create_multipart_upload()
            .bucket(bucket)
            .key(&file_id)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(bucket, error = %e, "Failed to initiate S3 multipart upload");
                tonic::Status::internal(format!("Failed to initiate S3 multipart upload: {}", e))
            })?;

        let upload_id = create_multipart_upload_output
            .upload_id()
            .ok_or_else(|| tonic::Status::internal("MinIO/S3 did not return an upload ID"))?;
        let mut completed_parts: Vec<CompletedPart> = Vec::new();
        let mut part_number = 1;

        while let Some(req) = stream.message().await? {
            let bytes = req.chunk_data.clone();
            let bytes_len = bytes.len();

            // Forward chunk to MinIO
            let upload_part_output = s3_client
                .upload_part()
                .bucket(bucket)
                .key(&file_id)
                .upload_id(upload_id)
                .part_number(part_number)
                .body(bytes.into())
                .send()
                .await
                .map_err(|e| {
                    tracing::error!(
                        bucket,
                        upload_id,
                        part_number,
                        error = %e,
                        "Failed to upload part to S3"
                    );
                    tonic::Status::internal(format!("Failed to upload part to S3: {}", e))
                })?;

            let e_tag = upload_part_output.e_tag().ok_or_else(|| {
                tracing::error!(
                    bucket,
                    upload_id,
                    part_number,
                    "MinIO/S3 did not return an ETag for the uploaded part"
                );
                tonic::Status::internal("MinIO/S3 did not return an ETag for the uploaded part")
            })?;

            // Cache the part receipt tag (required to finalize S3 uploads)
            completed_parts.push(
                CompletedPart::builder()
                    .e_tag(e_tag)
                    .part_number(part_number)
                    .build(),
            );

            tracing::debug!(part_number, bytes_len, "Uploaded part to S3");

            part_number += 1;
            total_bytes += req.chunk_data.len() as u64;
        }

        // stream is finished to assemble the file
        let completed_upload = CompletedMultipartUpload::builder()
            .set_parts(Some(completed_parts))
            .build();

        s3_client
            .complete_multipart_upload()
            .bucket(bucket)
            .key(&file_id)
            .upload_id(upload_id)
            .multipart_upload(completed_upload)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(
                    bucket,
                    upload_id,
                    error = %e,
                    "Failed to complete S3 multipart upload"
                );
                tonic::Status::internal(e.to_string())
            })?;

        tracing::info!(total_bytes, "Successfully saved upload");

        Ok(Response::new(UploadResponse {
            file_id: file_id,
            total_bytes_received: total_bytes,
        }))
    }
}
