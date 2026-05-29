// Original file: ../proto/transfer.proto

import type * as grpc from '@grpc/grpc-js'
import type { MethodDefinition } from '@grpc/proto-loader'
import type { UploadRequest as _transfer_UploadRequest, UploadRequest__Output as _transfer_UploadRequest__Output } from '../transfer/UploadRequest';
import type { UploadResponse as _transfer_UploadResponse, UploadResponse__Output as _transfer_UploadResponse__Output } from '../transfer/UploadResponse';

export interface AnalysisClient extends grpc.Client {
  UploadBinary(metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_transfer_UploadResponse__Output>): grpc.ClientWritableStream<_transfer_UploadRequest>;
  UploadBinary(metadata: grpc.Metadata, callback: grpc.requestCallback<_transfer_UploadResponse__Output>): grpc.ClientWritableStream<_transfer_UploadRequest>;
  UploadBinary(options: grpc.CallOptions, callback: grpc.requestCallback<_transfer_UploadResponse__Output>): grpc.ClientWritableStream<_transfer_UploadRequest>;
  UploadBinary(callback: grpc.requestCallback<_transfer_UploadResponse__Output>): grpc.ClientWritableStream<_transfer_UploadRequest>;
  uploadBinary(metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_transfer_UploadResponse__Output>): grpc.ClientWritableStream<_transfer_UploadRequest>;
  uploadBinary(metadata: grpc.Metadata, callback: grpc.requestCallback<_transfer_UploadResponse__Output>): grpc.ClientWritableStream<_transfer_UploadRequest>;
  uploadBinary(options: grpc.CallOptions, callback: grpc.requestCallback<_transfer_UploadResponse__Output>): grpc.ClientWritableStream<_transfer_UploadRequest>;
  uploadBinary(callback: grpc.requestCallback<_transfer_UploadResponse__Output>): grpc.ClientWritableStream<_transfer_UploadRequest>;
  
}

export interface AnalysisHandlers extends grpc.UntypedServiceImplementation {
  UploadBinary: grpc.handleClientStreamingCall<_transfer_UploadRequest__Output, _transfer_UploadResponse>;
  
}

export interface AnalysisDefinition extends grpc.ServiceDefinition {
  UploadBinary: MethodDefinition<_transfer_UploadRequest, _transfer_UploadResponse, _transfer_UploadRequest__Output, _transfer_UploadResponse__Output>
}
