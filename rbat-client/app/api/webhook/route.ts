import { type NextRequest, NextResponse } from "next/server";
import { Webhook } from "standardwebhooks";
import { saveAnalysis } from "@/lib/store";
import { analysisEvents } from "@/lib/events";

export async function POST(request: NextRequest) {
  try {
    const rawBody = await request.text();
    const webhookSecret =
      process.env.WEBHOOK_SECRET || "whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD";

    const wh = new Webhook(webhookSecret);
    const headers = {
      "webhook-id": request.headers.get("webhook-id") || "",
      "webhook-timestamp": request.headers.get("webhook-timestamp") || "",
      "webhook-signature": request.headers.get("webhook-signature") || "",
    };

    try {
      wh.verify(rawBody, headers);
    } catch (verifyError: any) {
      console.error("Webhook signature verification failed:", verifyError);
      return NextResponse.json({ error: "Invalid signature" }, { status: 401 });
    }

    const payload = JSON.parse(rawBody);
    console.log(`Received verified webhook: ${payload.event_type}`);

    if (payload.event_type === "analysis.completed") {
      const fileId = payload.data?.file_id;
      if (fileId) {
        saveAnalysis(fileId, payload.data);
        console.log(`Successfully stored analysis results for file: ${fileId}`);

        // Notify any active event streams of completion
        analysisEvents.emit(`complete:${fileId}`, payload.data);
      }
    }

    return NextResponse.json({ status: "success" });
  } catch (error: any) {
    console.error("Webhook receiver error:", error);
    return NextResponse.json(
      { error: error.message || "Internal server error" },
      { status: 500 },
    );
  }
}
