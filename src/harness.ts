import fs from "node:fs";
import path from "node:path";
import { redact } from "./text.ts";
import type { Finding } from "./types.ts";

export type ThreadStatus = "active" | "held" | "rejected" | "supported";

export interface ResearchThread {
  id: string;
  status: ThreadStatus;
  question: string;
  assessment: string;
  evidence: string;
  next: string;
  updatedAt: string;
}

interface BaselineEntry {
  id: string;
  fingerprint: string;
  ruleId: string;
  path: string;
  line: number;
}

const STATUSES = new Set<ThreadStatus>(["active", "held", "rejected", "supported"]);

function stateDir(root: string): string {
  return path.join(root, ".secure-droid");
}

function threadFile(root: string): string {
  return path.join(stateDir(root), "research.json");
}

function activityFile(root: string): string {
  return path.join(stateDir(root), "activity.jsonl");
}

function baselineFile(root: string): string {
  return path.join(stateDir(root), "baseline.json");
}

function writeJson(file: string, value: unknown): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temporary = `${file}.tmp`;
  fs.writeFileSync(temporary, JSON.stringify(value, null, 2));
  fs.renameSync(temporary, file);
}

function loadThreads(root: string): ResearchThread[] {
  const file = threadFile(root);
  if (!fs.existsSync(file)) return [];
  const parsed = JSON.parse(fs.readFileSync(file, "utf8")) as ResearchThread[];
  return Array.isArray(parsed) ? parsed : [];
}

export function listThreadIndex(root: string): string[] {
  return loadThreads(root).map((thread) => `${thread.id} ${thread.status} ${thread.question}`);
}

export function saveHypothesis(
  root: string,
  input: { question: string; assessment: string; evidence: string; next: string; status?: string },
): ResearchThread {
  const question = redact(input.question.trim());
  const assessment = redact(input.assessment.trim());
  const evidence = redact(input.evidence.trim());
  const next = redact(input.next.trim());
  if (question.length < 12 || assessment.length < 12 || evidence.length < 12 || next.length < 8) {
    throw new Error("A hypothesis needs a question, what was observed, the evidence or the missing check, and one next action.");
  }
  const status = (input.status?.trim() || "active") as ThreadStatus;
  if (!STATUSES.has(status)) throw new Error("Hypothesis status must be active, held, rejected, or supported.");
  const threads = loadThreads(root);
  const thread: ResearchThread = {
    id: `thr-${String(threads.length + 1).padStart(3, "0")}`,
    status,
    question,
    assessment,
    evidence,
    next,
    updatedAt: new Date().toISOString(),
  };
  writeJson(threadFile(root), [...threads, thread].slice(-40));
  return thread;
}

export function readThread(root: string, id: string): ResearchThread {
  const thread = loadThreads(root).find((item) => item.id === id);
  if (!thread) throw new Error(`Unknown research thread: ${id}`);
  return thread;
}

export function formatThreadIndex(root: string): string {
  const lines = listThreadIndex(root);
  if (lines.length === 0) return "No research threads. Save an unproven claim with action hypothesize. A thread is not a finding.";
  return ["Research index. Open one thread before you treat it as evidence.", ...lines.map((line) => `- ${line}`)].join("\n");
}

export function formatThread(thread: ResearchThread): string {
  return [
    `${thread.id} ${thread.status}`,
    `Question: ${thread.question}`,
    `Assessment: ${thread.assessment}`,
    `Evidence: ${thread.evidence}`,
    `Next: ${thread.next}`,
    "This thread is research state. Supported means the notes are ready for a line-pinned check. It is not a vulnerability, and it was not sent anywhere.",
  ].join("\n");
}

export function recordActivity(root: string, action: string, ok: boolean): void {
  if (!root || !fs.existsSync(root) || !fs.statSync(root).isDirectory()) return;
  const file = activityFile(root);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.appendFileSync(file, `${JSON.stringify({ t: new Date().toISOString(), action, ok })}\n`);
}

export function formatActivity(root: string): string {
  const file = activityFile(root);
  if (!fs.existsSync(file)) return "Harness activity is empty. This log records which SecureDroid actions ran. It does not prove a vulnerability.";
  const rows = fs
    .readFileSync(file, "utf8")
    .split(/\r?\n/)
    .filter((line) => line.length > 0)
    .slice(-200)
    .map((line) => JSON.parse(line) as { action?: string });
  const counts = new Map<string, number>();
  for (const row of rows) counts.set(row.action ?? "unknown", (counts.get(row.action ?? "unknown") ?? 0) + 1);
  const summary = [...counts.entries()].map(([action, count]) => `- ${action}: ${count}`).join("\n");
  const recent = rows
    .slice(-5)
    .map((row) => row.action ?? "unknown")
    .join(", ");
  return `Harness activity. This log records which SecureDroid actions ran. It does not prove a vulnerability.\n${summary}\nRecent: ${recent}`;
}

function findingEntries(findings: Finding[]): BaselineEntry[] {
  return findings
    .filter((finding) => finding.status === "open" || finding.status === "staged")
    .map((finding) => ({ id: finding.id, fingerprint: finding.fingerprint, ruleId: finding.ruleId, path: finding.path, line: finding.line }));
}

export function noteBaseline(root: string, findings: Finding[]): string {
  try {
    const current = findingEntries(findings);
    const file = baselineFile(root);
    if (!fs.existsSync(file)) {
      writeJson(file, current);
      return "Baseline saved from this scan. Later scans compare the finding set with it. A line that disappears is not proof the app is secure.";
    }
    const prior = JSON.parse(fs.readFileSync(file, "utf8")) as BaselineEntry[];
    const priorIds = new Map(prior.map((entry) => [entry.id, entry.fingerprint]));
    const currentIds = new Map(current.map((entry) => [entry.id, entry.fingerprint]));
    let added = 0;
    let removed = 0;
    let changed = 0;
    let same = 0;
    for (const [id, fingerprint] of currentIds) {
      if (!priorIds.has(id)) added += 1;
      else if (priorIds.get(id) !== fingerprint) changed += 1;
      else same += 1;
    }
    for (const id of priorIds.keys()) if (!currentIds.has(id)) removed += 1;
    return `Baseline comparison: ${same} unchanged, ${added} added, ${removed} absent, ${changed} fingerprint changed. Absence is not a pass.`;
  } catch {
    return "Baseline was not written.";
  }
}

export function refreshBaseline(root: string, findings: Finding[]): string {
  writeJson(baselineFile(root), findingEntries(findings));
  return "Baseline replaced with the current open and staged findings. The previous comparison point is gone.";
}
