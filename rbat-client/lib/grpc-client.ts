import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import path from "path";
import { ProtoGrpcType } from './proto/transfer';

const PROTO_PATH = path.join(process.cwd(), "../proto/transfer.proto");

const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
});

const protoDescriptor = grpc.loadPackageDefinition(packageDefinition) as unknown as ProtoGrpcType;
export const transfer = protoDescriptor.transfer;

// Fallback to local daemon, or read env (e.g. from docker environment)
const serverUrl = process.env.GRPC_SERVER_URL || "localhost:8080";

export const client = new transfer.Analysis(
  serverUrl,
  grpc.credentials.createInsecure(),
);

let UploadResponse = transfer.UploadResponse;

export function uploadBinary(
  filename: string,
  buffer: Buffer,
): Promise<typeof UploadResponse> {
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
