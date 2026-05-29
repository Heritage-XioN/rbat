// Original file: ../proto/transfer.proto


export interface UploadRequest {
  'filename'?: (string);
  'chunkData'?: (Buffer | Uint8Array | string);
}

export interface UploadRequest__Output {
  'filename'?: (string);
  'chunkData'?: (Buffer);
}
