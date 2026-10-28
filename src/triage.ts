import { collectFiles } from "./analysis.ts";
import { parseManifest } from "./manifest.ts";
import { ruleStillMatches } from "./rules.ts";
import { loadStore, saveStore } from "./store.ts";
import { containedRealpath, fingerprintOf, redact, sha256 } from "./text.ts";
import fs from "node:fs";
import type { Finding, SourceFile } from "./types.ts";

export function triageRepository(root: string): Finding[] {
  const data = loadStore(root);
  const files = collectFiles(root).files;
  const now = new Date().toISOString();
  for (const finding of data.findings) {
    if (finding.status === "fixed" || finding.status === "suppressed") continue;
    const file = files.find((item) => item.path === finding.path);
    const live = finding.ruleId === "LLM-INVESTIGATION" ? investigationLive(finding, file) : Boolean(file && ruleStillMatches(finding.ruleId, file, files));
    if (!live) {
      finding.status = "fixed";
      finding.verdict = { result: "rejected", reason: "The current source no longer matches this check." };
      finding.updatedAt = now;
      continue;
    }
    if (finding.verdict?.result === "upheld") continue;
    const strong = finding.confidence === "confirmed" || finding.confidence === "high";
    const exposed = finding.runtime?.exposure === "runtime-reachable" || finding.runtime?.exposure === "build-time";
    if (strong && exposed) {
      finding.verdict = {
        result: "upheld",
        reason: "The check still matches, and the call path or build setting makes it apply.",
      };
    } else {
      finding.verdict = {
        result: "withheld",
        reason: "The pattern is present, but the call path or confidence is not strong enough to report it as a vulnerability.",
      };
    }
    finding.updatedAt = now;
  }
  saveStore(root, data);
  return data.findings;
}

export function judgeFinding(
  root: string,
  findingId: string,
  decision: string,
  file: string,
  line: string,
  note: string,
): Finding {
  const data = loadStore(root);
  const finding = data.findings.find((item) => item.id === findingId);
  if (!finding) throw new Error(`Unknown finding: ${findingId}`);
  if (note.trim().length < 12) throw new Error("A verifier note must describe what you read.");
  const files = collectFiles(root).files;
  const source = files.find((item) => item.path === finding.path);
  const live = Boolean(source && ruleStillMatches(finding.ruleId, source, files));
  const cited = citedLine(root, file, line);
  if (decision === "reject") {
    if (live) throw new Error("The rule still matches this file. The verifier cannot dismiss a live finding.");
    finding.status = "fixed";
    finding.verdict = { result: "rejected", reason: note.trim() };
    finding.updatedAt = new Date().toISOString();
    saveStore(root, data);
    return finding;
  }
  if (decision !== "uphold") throw new Error("Verifier decision must be uphold or reject.");
  if (!live || !source) throw new Error("The rule does not match the current file, so there is nothing to uphold.");
  const strong = (finding.confidence === "confirmed" || finding.confidence === "high") && (finding.runtime?.exposure === "runtime-reachable" || finding.runtime?.exposure === "build-time");
  if (!strong && !connects(finding, source, cited)) {
    throw new Error("Cite the entry-point line that reaches this code. The evidence line alone does not make a conditional finding a vulnerability.");
  }
  finding.verdict = { result: "upheld", reason: note.trim() };
  finding.updatedAt = new Date().toISOString();
  saveStore(root, data);
  return finding;
}

function investigationLive(finding: Finding, file: SourceFile | undefined): boolean {
  if (!file) return false;
  const lineText = file.text.split(/\r?\n/)[finding.line - 1];
  if (lineText === undefined) return false;
  const source = sha256(redact(lineText)).slice(0, 16);
  return finding.fingerprint === fingerprintOf(["LLM-INVESTIGATION", finding.path, source]);
}

function citedLine(root: string, file: string, line: string): { path: string; text: string; line: number; file: SourceFile } {
  const relative = file.replace(/\\/g, "/").replace(/^\.\//, "");
  if (!relative || relative.split("/").includes("..")) throw new Error("The cited file must stay inside the repository.");
  const real = containedRealpath(root, relative);
  if (!real) throw new Error(`File is outside the repository or missing: ${relative}`);
  const lineNo = Number(line);
  if (!Number.isInteger(lineNo) || lineNo < 1) throw new Error("The verifier needs a real line number.");
  const text = fs.readFileSync(real, "utf8");
  const row = text.split(/\r?\n/)[lineNo - 1];
  if (!row || row.trim().length === 0) throw new Error("That line is empty or past the end of the file.");
  return { path: relative, text: row, line: lineNo, file: { path: relative, text } };
}

function connects(finding: Finding, source: SourceFile, cited: { path: string; text: string; file: SourceFile }): boolean {
  if (!isEntry(cited.file)) return false;
  const names = new Set<string>();
  const callable = enclosingName(source.text, finding.line);
  if (callable && callable.length >= 4) names.add(callable);
  for (const match of source.text.matchAll(/\b(?:class|object)\s+([A-Za-z_][A-Za-z0-9_]*)/g)) {
    if (match[1]) names.add(match[1]);
  }
  return [...names].some((name) => new RegExp(`\\b${name}\\b`).test(cited.text));
}

function isEntry(file: SourceFile): boolean {
  if (file.path.endsWith("AndroidManifest.xml")) {
    return parseManifest(file.path, file.text).components.some((component) => component.exported !== false);
  }
  return /\bonCreate\s*\(|\bonReceive\s*\(|\bfun\s+main\s*\(|\bvoid\s+main\s*\(|@ReactMethod\b/.test(file.text);
}

function enclosingName(text: string, line: number): string | undefined {
  const rows = text.split(/\r?\n/).slice(0, line);
  for (let index = rows.length - 1; index >= 0; index -= 1) {
    const row = rows[index] ?? "";
    const fun = /\bfun\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/.exec(row);
    if (fun?.[1]) return fun[1];
    const method = /\bvoid\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/.exec(row);
    if (method?.[1]) return method[1];
  }
  return undefined;
}
