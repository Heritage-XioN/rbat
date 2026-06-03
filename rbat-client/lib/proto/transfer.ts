import type * as grpc from "@grpc/grpc-js";
import type { MessageTypeDefinition } from "@grpc/proto-loader";

import type {
  AnalysisClient as _transfer_AnalysisClient,
  AnalysisDefinition as _transfer_AnalysisDefinition,
} from "./transfer/Analysis";
import type {
  UploadRequest as _transfer_UploadRequest,
  UploadRequest__Output as _transfer_UploadRequest__Output,
} from "./transfer/UploadRequest";
import type {
  UploadResponse as _transfer_UploadResponse,
  UploadResponse__Output as _transfer_UploadResponse__Output,
} from "./transfer/UploadResponse";

type SubtypeConstructor<
  Constructor extends new (
    ...args: any
  ) => any,
  Subtype,
> = {
  new (...args: ConstructorParameters<Constructor>): Subtype;
};

export interface ProtoGrpcType {
  transfer: {
    Analysis: SubtypeConstructor<
      typeof grpc.Client,
      _transfer_AnalysisClient
    > & { service: _transfer_AnalysisDefinition };
    UploadRequest: MessageTypeDefinition<
      _transfer_UploadRequest,
      _transfer_UploadRequest__Output
    >;
    UploadResponse: MessageTypeDefinition<
      _transfer_UploadResponse,
      _transfer_UploadResponse__Output
    >;
  };
}
