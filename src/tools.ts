import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const resolved = new Map<string, string | undefined>();

export function resolveTool(name: "semgrep" | "ast-grep"): string | undefined {
  if (resolved.has(name)) return resolved.get(name);
  const found = locate(name);
  resolved.set(name, found);
  return found;
}

function locate(name: "semgrep" | "ast-grep"): string | undefined {
  const candidates =
    name === "ast-grep"
      ? [path.join(ROOT, "node_modules", ".bin", "ast-grep"), "ast-grep"]
      : [path.join(ROOT, ".tools", "venv", "bin", "semgrep"), "semgrep"];
  for (const candidate of candidates) {
    if (candidate.includes("/") && !fs.existsSync(candidate)) continue;
    if (toolVersion(candidate, name)) return candidate;
  }
  return undefined;
}

function toolVersion(command: string, name: "semgrep" | "ast-grep"): boolean {
  const result = spawnSync(command, ["--version"], { encoding: "utf8" });
  if (result.status !== 0) return false;
  const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  return name === "ast-grep" ? /ast-grep/i.test(output) : /semgrep/i.test(output);
}
