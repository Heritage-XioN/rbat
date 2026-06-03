import { Redis } from "ioredis";
import { analysisEvents } from "./events";
import { logger } from "./logger";

const REDIS_URL = process.env.REDIS_URL || "redis://localhost:6379";

// We require separate clients for publishing and subscribing
export const redisPublisher = new Redis(REDIS_URL, {
  maxRetriesPerRequest: null,
});

export const redisSubscriber = new Redis(REDIS_URL, {
  maxRetriesPerRequest: null,
});

// Configure shared Redis subscriptions to bridge cluster-wide events to the local emitter
let isBridgeInitialized = false;

export function initRedisPubSubBridge() {
  if (isBridgeInitialized) return;
  isBridgeInitialized = true;

  // Listen to pattern matching completion or failure channels
  redisSubscriber.psubscribe("analysis:*", (err) => {
    if (err) {
      logger.error(`Failed to subscribe to Redis analysis channels: ${err}`);
    } else {
      logger.info("Successfully subscribed to Redis analysis:* channels");
    }
  });

  redisSubscriber.on("pmessage", (_pattern, channel, message) => {
    logger.debug(`Redis PubSub pattern message: channel=${channel}`);

    // Map: analysis:complete:fileId -> complete:fileId
    // Map: analysis:failed:fileId   -> failed:fileId
    const parts = channel.split(":");
    const status = parts[1]; // complete | failed
    const fileId = parts[2];

    if (fileId && (status === "complete" || status === "failed")) {
      try {
        const data = JSON.parse(message);
        analysisEvents.emit(`${status}:${fileId}`, data);
      } catch (parseErr: any) {
        logger.error(
          `Failed to parse PubSub message on channel ${channel}: ${parseErr.message || parseErr}`,
        );
      }
    }
  });
}
