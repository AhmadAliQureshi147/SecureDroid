import fs from "node:fs";
import path from "node:path";
import { detectFromFiles } from "./detect.ts";
import { isSourcePath } from "./detect.ts";
import { parseManifest } from "./manifest.ts";
import { assessRuntime } from "./runtime.ts";
import { findingsForFile } from "./rules.ts";
import { containedRealpath, fingerprintOf, toPosix } from "./text.ts";
import type { Detection, Draft, Finding, ProjectMap, SourceFile } from "./types.ts";
import { EMPTY_VERIFICATION } from "./types.ts";

const SKIP_DIRECTORIES = new Set([
  "node_modules",
  "build",
  ".gradle",
  ".git",
  ".dart_tool",
  "dist",
  ".secure-droid",
  ".idea",
  "Pods",
  "ios",
]);

const MAX_FILES = 4000;
const MAX_BYTES = 400_000;

export function collectFiles(root: string): { files: SourceFile[]; truncated: boolean } {
  const files: SourceFile[] = [];
  const realRoot = fs.realpathSync(root);
  const pending = [realRoot];
  let truncated = false;

  while (pending.length > 0) {
    const directory = pending.pop();
    if (!directory) break;
    let entries: fs.Dirent[] = [];
    try {
      entries = fs.readdirSync(directory, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.name.startsWith(".")) continue;
      if (SKIP_DIRECTORIES.has(entry.name)) continue;
      const full = path.join(directory, entry.name);
      const relative = toPosix(path.relative(realRoot, full));
      if (entry.isDirectory()) {
        const real = containedRealpath(realRoot, full);
        if (real) pending.push(real);
        continue;
      }
      if (!entry.isFile() || !isSourcePath(relative)) continue;
      if (files.length >= MAX_FILES) {
        truncated = true;
        continue;
      }
      const real = containedRealpath(realRoot, full);
      if (!real) continue;
      const info = fs.statSync(real);
      if (info.size > MAX_BYTES) {
        truncated = true;
        continue;
      }
      files.push({ path: relative, text: fs.readFileSync(real, "utf8") });
    }
  }

  files.sort((a, b) => a.path.localeCompare(b.path));
  return { files, truncated };
}

export function toFinding(item: Draft, now: string, files: SourceFile[] = []): Finding {
  const fingerprint = fingerprintOf([item.ruleId, item.path, item.fingerprintSource]);
  return {
    id: `${item.ruleId}:${item.path}:${fingerprint}`,
    title: item.title,
    language: item.language,
    path: item.path,
    line: item.line,
    severity: item.severity,
    confidence: item.confidence,
    category: item.category,
    ruleId: item.ruleId,
    detectionMethods: item.detectionMethods,
    evidence: item.evidence,
    attackScenario: item.attackScenario,
    preconditions: item.preconditions,
    why: item.why,
    recommendation: item.recommendation,
    recipe: item.recipe,
    runtime: assessRuntime(item.ruleId, item.confidence, { path: item.path, line: item.line }, files),
    verification: { ...EMPTY_VERIFICATION, checks: [] },
    status: "open",
    fingerprint,
    masvs: item.masvs,
    subject: item.subject,
    updatedAt: now,
  };
}

export function evaluate(files: SourceFile[], root = "."): {
  detection: Detection;
  map: ProjectMap;
  findings: Finding[];
} {
  const detection = detectFromFiles(files);
  const manifests = files
    .filter((file) => file.path.endsWith("AndroidManifest.xml"))
    .map((file) => parseManifest(file.path, file.text));
  const drafts = files.flatMap((file) => findingsForFile(file, files));
  const now = new Date().toISOString();
  const findings = drafts
    .map((item) => toFinding(item, now, files))
    .sort((a, b) => a.id.localeCompare(b.id))
    .slice(0, 200);
  const map: ProjectMap = {
    root,
    frameworks: detection.frameworks,
    languages: detection.languages,
    filesScanned: files.length,
    manifests,
    modules: detection.modules,
    entryPoints: manifests.flatMap((manifest) =>
      manifest.components.map((component) => ({
        kind: component.kind,
        name: component.name,
        path: manifest.path,
        line: component.line,
        exported: component.exported,
      })),
    ),
    limitations: detection.limitations,
  };
  return { detection, map, findings };
}

export function evaluateRepository(root: string): {
  detection: Detection;
  map: ProjectMap;
  findings: Finding[];
  truncated: boolean;
} {
  const collected = collectFiles(root);
  const result = evaluate(collected.files, root);
  if (collected.truncated) {
    result.detection.limitations.push("Some files were skipped because the scan limits were reached.");
    result.map.limitations = result.detection.limitations;
  }
  return { ...result, truncated: collected.truncated };
}
