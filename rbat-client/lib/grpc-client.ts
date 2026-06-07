import crypto from "node:crypto";
import path from "node:path";
import { Readable } from "node:stream";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import type { ProtoGrpcType } from "./proto/transfer";

const PROTO_PATH = path.join(
  process.cwd(),
  "../rbat-server/proto/transfer.proto",
);

const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
});

const protoDescriptor = grpc.loadPackageDefinition(
  packageDefinition,
) as unknown as ProtoGrpcType;
export const transfer = protoDescriptor.transfer;

// Fallback to local daemon, or read env (e.g. from docker environment)
const serverUrl = process.env.GRPC_SERVER_URL || "localhost:8080";

export const client = new transfer.Analysis(
  serverUrl,
  grpc.credentials.createInsecure(),
);

export function uploadBinary(
  filename: string,
  buffer: Buffer,
): Promise<{ file_id: string; total_bytes_received: number }> {
  return new Promise((resolve, reject) => {
    const call = client.UploadBinary((err: any, response: any) => {
      if (err) {
        reject(err);
      } else {
        resolve(response);
      }
    });

    const chunkSize = 64 * 1024; // 64 KB chunks
    let offset = 0;

    const sendNextChunk = () => {
      if (offset >= buffer.length) {
        call.end();
        return;
      }

      const end = Math.min(offset + chunkSize, buffer.length);
      const chunk = buffer.subarray(offset, end);
      offset = end;

      const req = {
        filename,
        chunk_data: chunk,
      };

      const canWrite = call.write(req);
      if (canWrite) {
        sendNextChunk();
      } else {
        call.once("drain", sendNextChunk);
      }
    };

    sendNextChunk();
  });
}

export function uploadBinaryStream(
  filename: string,
  stream: Readable,
): Promise<{ file_id: string; total_bytes_received: number; md5Hash: string }> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("md5");
    let totalBytes = 0;

    const call = client.UploadBinary((err: any, response: any) => {
      if (err) {
        reject(err);
      } else {
        resolve({
          file_id: response.file_id,
          total_bytes_received:
            Number(response.total_bytes_received) || totalBytes,
          md5Hash: hash.digest("hex"),
        });
      }
    });

    stream.on("data", (chunk: Buffer) => {
      // Feed hashing engine
      hash.update(chunk);
      totalBytes += chunk.length;

      const req = {
        filename,
        chunk_data: chunk,
      };

      const canWrite = call.write(req);
      if (!canWrite) {
        stream.pause();
        call.once("drain", () => {
          stream.resume();
        });
      }
    });

    stream.on("end", () => {
      call.end();
    });

    stream.on("error", (err) => {
      call.destroy(err);
      reject(err);
    });
  });
}
