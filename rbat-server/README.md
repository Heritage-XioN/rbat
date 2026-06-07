# rbat-server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/github/actions/workflow/status/Heritage-XioN/rbat/ci-rust.yml?style=for-the-badge&label=build)](https://github.com/Heritage-XioN/rbat/actions)
[![Rust MSRV](https://img.shields.io/badge/rustc-1.75+-orange.svg?style=for-the-badge&logo=rust)](https://blog.rust-lang.org/2023/12/28/Rust-1.75.0.html)

**rbat-server** is a high-performance backend daemon designed to handle streaming binary uploads and process security heuristics asynchronously. It integrates with MinIO / S3 object storage for binary persistence and dispatches structured analysis results to client consumers via cryptographically signed webhooks.

---

## Features

* **Multi-Protocol Service Endpoint**: A unified server handling gRPC streaming uploads (Tonic) and HTTP Webhook endpoints (Axum) on a single port.
* **S3 / MinIO Integration**: Streams binary files directly into AWS S3-compatible object storage via multipart uploading.
* **CPU-Bound Offloading**: Offloads heavy core binary analysis calculations to a Rayon CPU thread pool to keep the network loop non-blocking.
* **Signed Webhooks Dispatch**: signs and dispatches webhook events to clients with standard signature validation headers, utilizing exponential backoff and jittered retry strategies.
* **Production Configuration Enforcements**: Enforces security-sensitive configuration rules in production mode.

---

## Configuration

The server is configured via environment variables. Copy `.env.example` to `.env` to configure your environment:

| Variable | Description | Default |
|---|---|---|
| `HOST` | The bind address of the server | `0.0.0.0` |
| `PORT` | The bind port of the server | `8080` |
| `MINIO_ROOT_USER` | The MinIO access key root user | `admin` |
| `MINIO_ROOT_PASSWORD` | The MinIO secret key root password | `password123` |
| `MINIO_ENDPOINT` | The MinIO endpoint URL | `http://localhost:9000` |
| `WEBHOOK_TARGET_URL` | Destination client URL for analysis webhook dispatch | |
| `WEBHOOK_SECRET` | Secret key for signing outgoing webhooks | |
| `RUN_MODE` | Runtime environment mode (`development` or `production`) | `development` |

---

## Quick Start

### Launching via Docker Compose

The easiest way to run the server alongside its MinIO dependency:

```bash
docker compose up -d rbat_server
```

### Running Manually

Ensure you have MinIO running locally, then execute:

```bash
# Compile and run the daemon
cargo run -p rbat-server
```

---

## Usage Examples

### Streaming Upload via gRPC (Rust Client Example)

The following example demonstrates how to establish a gRPC channel and stream-upload a binary to the server:

```rust
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio_stream::wrappers::ReceiverStream;
use rbat_server::transfer::{UploadRequest, analysis_client::AnalysisClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = AnalysisClient::connect("http://127.0.0.1:8080").await?;
    let mut file = File::open("my_binary.exe").await?;
    let (tx, rx) = tokio::sync::mpsc::channel(4);

    tokio::spawn(async move {
        let mut buffer = vec![0u8; 64 * 1024]; // 64KB chunks
        while let Ok(bytes_read) = file.read(&mut buffer).await {
            if bytes_read == 0 { break; }
            let request_chunk = UploadRequest {
                filename: "my_binary.exe".to_string(),
                chunk_data: buffer[..bytes_read].to_vec(),
            };
            if tx.send(request_chunk).await.is_err() { break; }
        }
    });

    let request_stream = ReceiverStream::new(rx);
    let response = client.upload_binary(tonic::Request::new(request_stream)).await?;
    let result = response.into_inner();

    println!("Uploaded successfully. File ID: {}", result.file_id);
    Ok(())
}
```

### Incoming Webhook Triggers

The server listens on `POST /webhooks` for incoming webhook triggers.

```json
{
  "event_type": "analysis.start",
  "data": {
    "file_id": "936da01f-9abd-4d9d-80c7-02af85c822a8"
  }
}
```

---

## Links

* [Documentation (docs.rs)](https://docs.rs/rbat-server)
* [Repository (GitHub)](https://github.com/Heritage-XioN/rbat)
* [Contributing Guide](../CONTRIBUTING.md)

---

## License

This project is licensed under the MIT License. See the [LICENSE](../LICENSE) file for details.