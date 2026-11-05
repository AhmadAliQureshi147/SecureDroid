import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { containedRealpath } from "./text.ts";
import type { Finding } from "./types.ts";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
let resolved: string | undefined | null = null;

export interface GraphPathSummary {
  confidence: "extracted" | "inferred" | "none" | "unknown";
  summary: string;
}

export function graphifyInstalled(): boolean {
  return resolveGraphify() !== undefined;
}

export function summarizeGraphPath(text: string): GraphPathSummary {
  const clean = text.trim();
  if (!clean || /No directed path|No path|no matching node|not found/i.test(clean)) {
    return { confidence: "none", summary: "No directed path in the code map." };
  }
  const route = clean.split("\n").find((line) => line.includes("-->") || line.includes("<--"))?.trim();
  if (/\[INFERRED\b/i.test(clean)) {
    return { confidence: "inferred", summary: route ?? "The code map inferred a path. The weakest hop was not read directly from source." };
  }
  if (/\[EXTRACTED\b/i.test(clean)) {
    return { confidence: "extracted", summary: route ?? "Every hop on this path was extracted from source." };
  }
  return { confidence: "unknown", summary: clean.split("\n")[0] ?? "The code map returned no path." };
}

export function graphContext(
  projectRoot: string,
  findings: Finding[],
  entryPoints: Array<{ name: string; exported: boolean | "unspecified"; kind: string }>,
): string {
  const binary = resolveGraphify();
  if (!binary) {
    return "Graph context: graphify is not installed. The review uses SecureDroid's own call path. A missing map is not a pass.";
  }
  const graph = ensureGraph(binary, projectRoot);
  if (!graph) {
    return "Graph context: the code map was not built. The review uses SecureDroid's own call path.";
  }
  const entry = primaryEntry(entryPoints);
  const hubs = godNodes(binary, graph);
  const lines = findings
    .filter((finding) => finding.status === "open" || finding.status === "staged")
    .map((finding) => ({ finding, target: targetSymbol(projectRoot, finding.path) }))
    .filter((item): item is { finding: Finding; target: string } => Boolean(item.target))
    .filter((item, index, all) => all.findIndex((other) => other.target === item.target) === index)
    .slice(0, 6)
    .map((item) => {
      const result = run(binary, ["path", entry, item.target, "--graph", graph], projectRoot, 20_000);
      const summary = summarizeGraphPath(`${result.stdout}\n${result.stderr}`);
      const meaning =
        summary.confidence === "extracted"
          ? "Read the files on this path before judging the line. This does not by itself make it a vulnerability."
          : summary.confidence === "inferred"
            ? "Treat this path as unconfirmed. Do not mark the finding runtime-reachable from the map alone."
            : "Do not upgrade this finding from the map.";
      return `- ${entry} -> ${item.target} (${item.finding.ruleId}): ${summary.confidence}. ${summary.summary} ${meaning}`;
    });
  return [
    "Graph context:",
    "This is a local code map of calls and imports. It does not decide vulnerabilities and it does not edit files.",
    hubs ? `Most-connected symbols: ${hubs}` : "",
    ...lines,
  ]
    .filter((line) => line.length > 0)
    .join("\n");
}

function ensureGraph(binary: string, projectRoot: string): string | undefined {
  const outDir = path.join(projectRoot, ".secure-droid");
  const graph = path.join(outDir, "graphify-out", "graph.json");
  fs.mkdirSync(outDir, { recursive: true });
  const result = run(
    binary,
    ["extract", projectRoot, "--code-only", "--no-cluster", "--out", outDir],
    projectRoot,
    120_000,
  );
  if (!fs.existsSync(graph)) return undefined;
  if (result.status !== 0 && !fs.existsSync(graph)) return undefined;
  return graph;
}

function godNodes(binary: string, graph: string): string {
  const result = run(binary, ["god-nodes", "--top", "5", "--graph", graph], path.dirname(graph), 20_000);
  const names = [...result.stdout.matchAll(/^\s*\d+\.\s+(\S+)/gm)].map((match) => match[1] ?? "").filter(Boolean);
  return names.join(", ");
}

function primaryEntry(entryPoints: Array<{ name: string; exported: boolean | "unspecified"; kind: string }>): string {
  const activities = entryPoints.filter((entry) => entry.kind === "activity" && entry.exported !== false);
  const main = activities.find((entry) => /Main|Launcher/i.test(entry.name));
  const chosen = main ?? activities[0] ?? entryPoints[0];
  return chosen ? (chosen.name.split(".").pop() ?? "main") : "main";
}

function targetSymbol(projectRoot: string, relativePath: string): string | undefined {
  if (relativePath.endsWith(".xml") || relativePath.endsWith(".gradle") || relativePath.endsWith(".kts")) return undefined;
  const real = containedRealpath(projectRoot, relativePath);
  if (!real) return path.basename(relativePath).replace(/\.[^.]+$/, "");
  const text = fs.readFileSync(real, "utf8");
  const named = /\b(?:class|object|interface|fun|void|function)\s+([A-Za-z_][A-Za-z0-9_]*)/.exec(text);
  return named?.[1] ?? path.basename(relativePath).replace(/\.[^.]+$/, "");
}

function resolveGraphify(): string | undefined {
  if (resolved !== null) return resolved;
  const candidates = [
    path.join(ROOT, ".tools", "graphify-venv", "bin", "graphify"),
    path.join(ROOT, ".tools", "graphify-venv", "Scripts", "graphify.exe"),
    "graphify",
  ];
  for (const candidate of candidates) {
    if (candidate.includes(path.sep) && !fs.existsSync(candidate)) continue;
    const result = spawnSync(candidate, ["--help"], { encoding: "utf8", timeout: 15_000 });
    if (result.status === 0 && /graphify/i.test(`${result.stdout}\n${result.stderr}`)) {
      resolved = candidate;
      return candidate;
    }
  }
  resolved = undefined;
  return undefined;
}

function run(binary: string, args: string[], cwd: string, timeout: number): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(binary, args, {
    cwd,
    encoding: "utf8",
    timeout,
    killSignal: "SIGKILL",
    env: { ...process.env, GRAPHIFY_BACKEND: "none" },
  });
  return { status: result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}
