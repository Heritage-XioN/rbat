// Original file: ../proto/transfer.proto

import type { Long } from '@grpc/proto-loader';

export interface UploadResponse {
  'fileId'?: (string);
  'totalBytesReceived'?: (number | string | Long);
}

export interface UploadResponse__Output {
  'fileId'?: (string);
  'totalBytesReceived'?: (Long);
}
