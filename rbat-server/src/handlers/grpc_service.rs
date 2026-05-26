use std::sync::Arc;

use crate::{
    AppState,
    transfer::{UploadRequest, UploadResponse, analysis_server::Analysis},
};

use aws_sdk_s3::types::CompletedMultipartUpload;
use aws_sdk_s3::types::CompletedPart;
use tonic::{Request, Response, Status, Streaming};
use uuid::Uuid;

#[derive(Debug)]
pub struct GRPCservice {
    pub state: Arc<AppState>,
}

#[tonic::async_trait]
impl Analysis for GRPCservice {
    async fn upload_binary(
        &self,
        request: Request<Streaming<UploadRequest>>,
    ) -> Result<Response<UploadResponse>, Status> {
        let mut stream = request.into_inner();
        let s3_client = &self.state.s3_client;
        let bucket = "pt-compromised-binaries";
        let file_id = Uuid::new_v4().to_string();
        let mut total_bytes = 0;

        // Initiate the Multipart upload in MinIO
        let create_multipart_upload_output = s3_client
            .create_multipart_upload()
            .bucket(bucket)
            .key(&file_id)
            .send()
            .await
            .map_err(|e| tonic::Status::internal(e.to_string()))?;

        let upload_id = create_multipart_upload_output.upload_id().unwrap();
        let mut completed_parts: Vec<CompletedPart> = Vec::new();
        let mut part_number = 1;

        while let Some(req) = stream.message().await? {
            let bytes = req.chunk_data.clone();

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
                .map_err(|e| tonic::Status::internal(e.to_string()))?;

            // Cache the part receipt tag (required to finalize S3 uploads)
            completed_parts.push(
                CompletedPart::builder()
                    .e_tag(upload_part_output.e_tag().unwrap())
                    .part_number(part_number)
                    .build(),
            );

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
            .map_err(|e| tonic::Status::internal(e.to_string()))?;

        println!("Successfully saved upload. Total bytes: {}", total_bytes);

        Ok(Response::new(UploadResponse {
            file_id: file_id,
            total_bytes_received: total_bytes,
        }))
    }
}
