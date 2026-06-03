type LogLevel = "debug" | "info" | "warn" | "error";

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

function getRequiredLogLevel(): number {
  const envLevel = (process.env.LOG_LEVEL || "").toLowerCase();
  if (envLevel in LOG_LEVELS) {
    return LOG_LEVELS[envLevel as LogLevel];
  }
  // Default to 'debug' in development, 'info' in production/other environments
  return process.env.NODE_ENV === "development"
    ? LOG_LEVELS.debug
    : LOG_LEVELS.info;
}

const currentLevel = getRequiredLogLevel();

function shouldLog(level: LogLevel): boolean {
  return LOG_LEVELS[level] >= currentLevel;
}

function formatMessage(level: LogLevel, message: string): string {
  const timestamp = new Date().toISOString();
  return `[${level.toUpperCase()}] ${timestamp} - ${message}`;
}

export const logger = {
  debug(message: string, ...args: any[]) {
    if (shouldLog("debug")) {
      console.debug(formatMessage("debug", message), ...args);
    }
  },

  info(message: string, ...args: any[]) {
    if (shouldLog("info")) {
      console.info(formatMessage("info", message), ...args);
    }
  },

  warn(message: string, ...args: any[]) {
    if (shouldLog("warn")) {
      console.warn(formatMessage("warn", message), ...args);
    }
  },

  error(message: string, ...args: any[]) {
    if (shouldLog("error")) {
      console.error(formatMessage("error", message), ...args);
    }
  },
};
