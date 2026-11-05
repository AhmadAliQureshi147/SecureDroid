import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const BRAIN_MODEL = "grok-4.7-high-fast";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

export function loadProjectEnv(root = ROOT): void {
  const file = path.join(root, ".env");
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const split = trimmed.indexOf("=");
    if (split < 1) continue;
    const key = trimmed.slice(0, split).trim();
    let value = trimmed.slice(split + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

export function brainConfigured(): boolean {
  loadProjectEnv();
  const key = process.env.CURSOR_API_KEY ?? "";
  return key.startsWith("crsr_") && key.length > 20;
}

export function brainStatus(): string {
  return brainConfigured()
    ? `Review brain: ${BRAIN_MODEL}. The Cursor API key is configured for this project and is not shown.`
    : `Review brain: ${BRAIN_MODEL}. Put CURSOR_API_KEY in the gitignored .env file. Do not put the key in source.`;
}
