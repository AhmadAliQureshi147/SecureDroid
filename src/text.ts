import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export function sha256(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

export function fingerprintOf(parts: string[]): string {
  return sha256(parts.join("\n")).slice(0, 16);
}

export function toPosix(filePath: string): string {
  return filePath.split(path.sep).join("/");
}

export function lineAt(text: string, index: number): number {
  let line = 1;
  const end = Math.min(index, text.length);
  for (let i = 0; i < end; i++) {
    if (text.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

export function lineText(text: string, line: number): string {
  return text.split(/\r?\n/)[line - 1] ?? "";
}

export function redact(text: string): string {
  return text
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "<redacted-private-key>")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "<redacted>")
    .replace(/\bAIza[0-9A-Za-z\-_]{35}\b/g, "<redacted>")
    .replace(/(["'`])(?:\\.|(?!\1).){8,}\1/g, "<redacted>");
}

export function resolveInside(root: string, target: string): string {
  const base = path.resolve(root);
  if (base === path.parse(base).root) {
    throw new Error("Refusing to use the filesystem root as a project.");
  }
  const resolved = path.resolve(base, target);
  const relative = path.relative(base, resolved);
  if (relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative))) {
    return resolved;
  }
  throw new Error(`Path escapes the repository: ${target}`);
}

export function containedRealpath(root: string, target: string): string | undefined {
  const resolved = resolveInside(root, target);
  if (!fs.existsSync(resolved)) return undefined;
  const realRoot = fs.realpathSync(root);
  const realTarget = fs.realpathSync(resolved);
  const relative = path.relative(realRoot, realTarget);
  if (relative.startsWith("..") || path.isAbsolute(relative)) return undefined;
  return realTarget;
}
