import crypto from "node:crypto";
import { type NextRequest, NextResponse } from "next/server";
import { Webhook } from "standardwebhooks";
import { uploadBinary } from "@/lib/grpc-client";
import { logger } from "@/lib/logger";

export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData();
    const file = formData.get("file") as File | null;
    if (!file) {
      return NextResponse.json({ error: "No file provided" }, { status: 400 });
    }

    const arrayBuffer = await file.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    // Compute MD5 hash
    const md5Hash = crypto.createHash("md5").update(buffer).digest("hex");

    // 1. Stream the upload to the gRPC daemon
    const uploadRes = await uploadBinary(file.name, buffer);
    const { file_id } = uploadRes;

    // 2. Dispatch analysis.start webhook to the Rust backend to kick off analysis
    const webhookSecret = process.env.WEBHOOK_SECRET;
    if (!webhookSecret) {
      if (process.env.NODE_ENV === "production") {
        throw new Error(
          "Missing WEBHOOK_SECRET environment variable in production!",
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
      fileName: file.name,
      md5Hash,
      size: file.size,
    });
  } catch (error: any) {
    logger.error(`Upload route error: ${error.message || error}`);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 },
    );
  }
}
