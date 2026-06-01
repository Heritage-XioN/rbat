import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const STORE_DIR =
  process.env.ANALYSIS_STORE_PATH ||
  path.join(os.tmpdir(), "rbat-analysis-store");

if (!fs.existsSync(STORE_DIR)) {
  fs.mkdirSync(STORE_DIR, { recursive: true, mode: 0o700 });
  // Ensure strict directory permissions (owner read/write/execute only)
  try {
    fs.chmodSync(STORE_DIR, 0o700);
  } catch (err) {
    // If chmod fails (e.g. on Windows), we still proceed
  }
}

export function saveAnalysis(fileId: string, data: any) {
  const filePath = path.join(STORE_DIR, `${fileId}.json`);
  // Ensure owner read/write only permissions on creation
  fs.writeFileSync(filePath, JSON.stringify(data), {
    encoding: "utf-8",
    mode: 0o600,
  });
}

export function getAnalysis(fileId: string): any | null {
  const filePath = path.join(STORE_DIR, `${fileId}.json`);
  if (fs.existsSync(filePath)) {
    const content = fs.readFileSync(filePath, "utf-8");
    return JSON.parse(content);
  }
  return null;
}
