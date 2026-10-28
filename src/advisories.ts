import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { requirementIds } from "./standards.ts";
import type { Draft, SourceFile } from "./types.ts";

interface SnapshotAdvisory {
  id: string;
  summary: string;
  ecosystem: "Maven" | "npm";
  name: string;
  events: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
}

const SNAPSHOT = JSON.parse(
  fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "advisories", "osv-snapshot.json"), "utf8"),
) as { advisories: SnapshotAdvisory[] };

export function dependencyFindings(file: SourceFile): Draft[] {
  const packages = file.path.endsWith("package.json") ? npmPackages(file.text) : file.path.endsWith(".gradle") || file.path.endsWith(".gradle.kts") ? mavenPackages(file.text) : [];
  const found: Draft[] = [];
  for (const item of packages) {
    const advisory = SNAPSHOT.advisories.find((entry) => entry.ecosystem === item.ecosystem && entry.name === item.name && affects(item.version, entry.events));
    if (!advisory) continue;
    found.push({
        ruleId: "DEPENDENCY-ADVISORY",
        title: `${advisory.id}: ${advisory.summary}`,
        language: item.ecosystem === "npm" ? "javascript" : "gradle",
        path: file.path,
        line: item.line,
        severity: "P1",
        confidence: "high",
        category: "dependencies",
        detectionMethods: ["config"],
        evidence: [{ path: file.path, line: item.line, description: `${item.name}@${item.version} is inside ${advisory.id}.` }],
        attackScenario: "The shipped dependency is in the affected range recorded by the OSV snapshot.",
        preconditions: ["This declared version is the one resolved into the release artifact."],
        why: advisory.summary,
        recommendation: `Upgrade ${item.name} to a version outside ${advisory.id}. The local snapshot is not a complete advisory database.`,
        recipe: "manual",
        masvs: requirementIds("DEPENDENCY-ADVISORY"),
        fingerprintSource: `${advisory.id}:${item.name}:${item.version}`,
    });
  }
  return found;
}

function mavenPackages(text: string): Array<{ ecosystem: "Maven"; name: string; version: string; line: number }> {
  const found = [];
  const pattern = /(?:implementation|api|compileOnly|runtimeOnly)\s*\(?\s*["']([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([0-9][^"']*)["']/g;
  for (const match of text.matchAll(pattern)) {
    const version = match[3] ?? "";
    if (version.includes("$") || version.includes("+")) continue;
    found.push({ ecosystem: "Maven" as const, name: `${match[1]}:${match[2]}`, version, line: lineOf(text, match.index ?? 0) });
  }
  return found;
}

function npmPackages(text: string): Array<{ ecosystem: "npm"; name: string; version: string; line: number }> {
  let parsed: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  try {
    parsed = JSON.parse(text) as typeof parsed;
  } catch {
    return [];
  }
  const found = [];
  for (const [name, version] of Object.entries({ ...parsed.dependencies, ...parsed.devDependencies })) {
    const concrete = version.replace(/^[\^~>=<]*/, "");
    if (!/^[0-9]/.test(concrete)) continue;
    const line = lineOf(text, text.indexOf(`"${name}"`));
    found.push({ ecosystem: "npm" as const, name, version: concrete, line });
  }
  return found;
}

function affects(version: string, events: SnapshotAdvisory["events"]): boolean {
  let open = false;
  for (const event of events) {
    if (event.introduced !== undefined) open = compareVersions(version, event.introduced) >= 0;
    if (event.fixed !== undefined && compareVersions(version, event.fixed) >= 0) open = false;
    if (event.last_affected !== undefined) open = compareVersions(version, event.last_affected) <= 0;
  }
  return open;
}

function compareVersions(left: string, right: string): number {
  const a = left.split(".").map((part) => Number.parseInt(part, 10) || 0);
  const b = right.split(".").map((part) => Number.parseInt(part, 10) || 0);
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const diff = (a[index] ?? 0) - (b[index] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function lineOf(text: string, index: number): number {
  let line = 1;
  for (let cursor = 0; cursor < index && cursor < text.length; cursor += 1) {
    if (text[cursor] === "\n") line += 1;
  }
  return line;
}
