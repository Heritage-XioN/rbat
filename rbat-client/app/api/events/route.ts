import type { NextRequest } from "next/server";
import { analysisEvents } from "@/lib/events";
import { initRedisPubSubBridge } from "@/lib/redis";
import { getAnalysis } from "@/lib/store";

export async function GET(request: NextRequest) {
  // Ensure Redis PubSub bridge is active
  initRedisPubSubBridge();

  const { searchParams } = new URL(request.url);
  const fileId = searchParams.get("fileId");

  if (!fileId) {
    return new Response("Missing fileId parameter", { status: 400 });
  }

  const stream = new ReadableStream({
    start(controller) {
      const encoder = new TextEncoder();

      // If the analysis is already complete or failed and cached in our filesystem store, return it immediately.
      const existingData = getAnalysis(fileId);
      if (existingData) {
        if (existingData.error) {
          controller.enqueue(
            encoder.encode(
              `event: failed\ndata: ${JSON.stringify(existingData)}\n\n`,
            ),
          );
        } else {
          controller.enqueue(
            encoder.encode(
              `event: complete\ndata: ${JSON.stringify(existingData)}\n\n`,
            ),
          );
        }
        controller.close();
        return;
      }

      // Event listener for when the analysis completing webhook fires
      const onComplete = (data: any) => {
        controller.enqueue(
          encoder.encode(`event: complete\ndata: ${JSON.stringify(data)}\n\n`),
        );
        controller.close();
      };

      const onFailure = (data: any) => {
        controller.enqueue(
          encoder.encode(`event: failed\ndata: ${JSON.stringify(data)}\n\n`),
        );
        controller.close();
      };

      analysisEvents.once(`complete:${fileId}`, onComplete);
      analysisEvents.once(`failed:${fileId}`, onFailure);

      // Clean up event listeners if the client aborts the connection (e.g. page closes)
      request.signal.addEventListener("abort", () => {
        analysisEvents.off(`complete:${fileId}`, onComplete);
        analysisEvents.off(`failed:${fileId}`, onFailure);
      });
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
    },
  });
}
