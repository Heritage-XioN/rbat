import { EventEmitter } from "events";

const globalForEvents = global as typeof globalThis & {
  analysisEvents?: EventEmitter;
};

if (!globalForEvents.analysisEvents) {
  globalForEvents.analysisEvents = new EventEmitter();
  globalForEvents.analysisEvents.setMaxListeners(100);
}

export const analysisEvents = globalForEvents.analysisEvents;
