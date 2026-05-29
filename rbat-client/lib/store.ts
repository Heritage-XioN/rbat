import fs from "fs";
import path from "path";
import os from "os";

const STORE_DIR = path.join(os.tmpdir(), "rbat-analysis-store");

if (!fs.existsSync(STORE_DIR)) {
  fs.mkdirSync(STORE_DIR, { recursive: true });
}

export function saveAnalysis(fileId: string, data: any) {
  const filePath = path.join(STORE_DIR, `${fileId}.json`);
  fs.writeFileSync(filePath, JSON.stringify(data), "utf-8");
}

export function getAnalysis(fileId: string): any | null {
  const filePath = path.join(STORE_DIR, `${fileId}.json`);
  if (fs.existsSync(filePath)) {
    const content = fs.readFileSync(filePath, "utf-8");
    return JSON.parse(content);
  }
  return null;
}
