import crypto from "node:crypto";
import { Readable } from "node:stream";
import { type NextRequest, NextResponse } from "next/server";
import { Webhook } from "standardwebhooks";
import { uploadBinaryStream } from "@/lib/grpc-client";
import { logger } from "@/lib/logger";

export async function POST(request: NextRequest) {
  try {
    const contentType = request.headers.get("content-type") || "";
    let file_id = "";
    let fileName = "binary";
    let md5Hash = "";
    let size = 0;

    if (contentType.includes("multipart/form-data")) {
      const formData = await request.formData();
      const file = formData.get("file") as File | null;
      if (!file) {
        return NextResponse.json(
          { error: "No file provided" },
          { status: 400 },
        );
      }

      // Enforce early max size limit (50MB) to prevent memory exhaustion
      if (file.size > 50 * 1024 * 1024) {
        return NextResponse.json(
          { error: "File size exceeds the 50MB limit" },
          { status: 413 },
        );
      }

      fileName = file.name;
      size = file.size;

      // Stream the File object directly to avoid buffering the full ArrayBuffer in memory
      const fileStream = Readable.fromWeb(file.stream() as any);
      const uploadRes = await uploadBinaryStream(fileName, fileStream);
      file_id = uploadRes.file_id;
      md5Hash = uploadRes.md5Hash;
      size = uploadRes.total_bytes_received;
    } else {
      const searchParams = request.nextUrl.searchParams;
      fileName = searchParams.get("filename") || "binary";
      const bodyStream = request.body;
      if (!bodyStream) {
        return NextResponse.json(
          { error: "No body stream provided" },
          { status: 400 },
        );
      }

      const nodeStream = Readable.fromWeb(bodyStream as any);
      const uploadRes = await uploadBinaryStream(fileName, nodeStream);
      file_id = uploadRes.file_id;
      md5Hash = uploadRes.md5Hash;
      size = uploadRes.total_bytes_received;
    }

    // Dispatch analysis.start webhook to the Rust backend to kick off analysis
    const webhookSecret = process.env.WEBHOOK_SECRET;
    if (!webhookSecret) {
      if (process.env.NODE_ENV !== "development") {
        throw new Error(
          `Missing WEBHOOK_SECRET environment variable in ${process.env.NODE_ENV || "production"}!`,
        );
      }
      logger.warn(
        "WEBHOOK_SECRET is not set. Falling back to default development key.",
      );
    }
    const secret = webhookSecret || "whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD";

    const webhookReceiverUrl =
      process.env.WEBHOOK_RECEIVER_URL || "http://localhost:8080/webhooks";

    const wh = new Webhook(secret);
    const eventId = crypto.randomUUID();
    const timestamp = new Date();
    const payload = {
      event_type: "analysis.start",
      data: {
        file_id: file_id,
      },
    };
    const payloadStr = JSON.stringify(payload);
    const signature = wh.sign(eventId, timestamp, payloadStr);

    logger.info(
      `Sending analysis.start webhook to ${webhookReceiverUrl} for file ${file_id}`,
    );
    const webhookResponse = await fetch(webhookReceiverUrl, {
      method: "POST",
      headers: {
        "webhook-id": eventId,
        "webhook-timestamp": Math.floor(timestamp.getTime() / 1000).toString(),
        "webhook-signature": signature,
        "event-type": "analysis.start",
        "delivery-id": eventId,
        "content-type": "application/json",
      },
      body: payloadStr,
    });

    if (!webhookResponse.ok) {
      logger.error(
        `Webhook daemon failed with status ${webhookResponse.status}`,
      );
      return NextResponse.json(
        { error: "Failed to trigger analysis" },
        { status: 500 },
      );
    }

    return NextResponse.json({
      fileId: file_id,
      fileName,
      md5Hash,
      size,
    });
  } catch (error: any) {
    logger.error(`Upload route error: ${error.message || error}`);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 },
    );
  }
}
