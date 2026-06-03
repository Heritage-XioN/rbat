import { type NextRequest, NextResponse } from "next/server";
import { Webhook } from "standardwebhooks";
import { logger } from "@/lib/logger";
import { redisPublisher } from "@/lib/redis";
import { saveAnalysis } from "@/lib/store";

export async function POST(request: NextRequest) {
  try {
    const rawBody = await request.text();
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

    const wh = new Webhook(secret);
    const headers = {
      "webhook-id": request.headers.get("webhook-id") || "",
      "webhook-timestamp": request.headers.get("webhook-timestamp") || "",
      "webhook-signature": request.headers.get("webhook-signature") || "",
    };

    try {
      wh.verify(rawBody, headers);
    } catch (_verifyError: any) {
      logger.warn("Webhook signature verification failed");
      return NextResponse.json({ error: "Invalid signature" }, { status: 401 });
    }

    const payload = JSON.parse(rawBody);
    logger.info(`Received verified webhook: ${payload.event_type}`);

    if (payload.event_type === "analysis.completed") {
      const fileId = payload.data?.file_id;
      if (fileId) {
        saveAnalysis(fileId, payload.data);
        logger.info(`Successfully stored analysis results for file: ${fileId}`);

        // Notify any active event streams of completion via Redis
        await redisPublisher.publish(
          `analysis:complete:${fileId}`,
          JSON.stringify(payload.data),
        );
      }
    }

    if (payload.event_type === "analysis.failed") {
      const fileId = payload.data?.file_id;
      if (fileId) {
        //saveAnalysis(fileId, payload.data);
        logger.error(`Error processing file with id: ${fileId}`);

        // Notify any active event streams of completion via Redis
        await redisPublisher.publish(
          `analysis:failed:${fileId}`,
          JSON.stringify(payload.data),
        );
      }
    }

    return NextResponse.json({ status: "success" });
  } catch (error: any) {
    logger.error("Webhook receiver error", error);
    return NextResponse.json(
      { error: error.message || "Internal server error" },
      { status: 500 },
    );
  }
}
