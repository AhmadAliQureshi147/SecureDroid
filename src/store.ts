import fs from "node:fs";
import path from "node:path";
import { collectFiles, evaluateRepository, toFinding } from "./analysis.ts";
import { languageOf } from "./detect.ts";
import { proposePatch, reviewChange, unifiedDiff } from "./patch.ts";
import { MASVS_REQUIREMENTS, requirementIds } from "./standards.ts";
import { containedRealpath, fingerprintOf, redact, sha256 } from "./text.ts";
import type { Category, ExceptionRecord, Finding, Severity, StagedChange, StoreData, Verification } from "./types.ts";

export function storeFile(root: string): string {
  return path.join(root, ".secure-droid", "store.json");
}

export function emptyStore(): StoreData {
  return { version: 1, findings: [], exceptions: [], staged: [] };
}

export function loadStore(root: string): StoreData {
  const file = storeFile(root);
  if (!fs.existsSync(file)) return emptyStore();
  const parsed = JSON.parse(fs.readFileSync(file, "utf8")) as StoreData;
  return {
    version: 1,
    findings: parsed.findings ?? [],
    exceptions: parsed.exceptions ?? [],
    staged: parsed.staged ?? [],
  };
}

export function saveStore(root: string, data: StoreData): void {
  const file = storeFile(root);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temporary = `${file}.tmp`;
  fs.writeFileSync(temporary, JSON.stringify(data, null, 2));
  fs.renameSync(temporary, file);
}

function applyException(finding: Finding, exceptions: ExceptionRecord[]): Finding {
  const match = exceptions.find((item) => item.findingId === finding.id && item.fingerprint === finding.fingerprint);
  if (!match) return finding;
  return { ...finding, status: "suppressed" };
}

export function mergeFindings(previous: Finding[], next: Finding[], exceptions: ExceptionRecord[]): Finding[] {
  const fresh = next.map((finding) => {
    const prior = previous.find((item) => item.id === finding.id && item.fingerprint === finding.fingerprint);
    const base = applyException(finding, exceptions);
    if (prior?.verdict?.result === "upheld") {
      const staged = prior.status === "staged" && base.status === "open";
      return {
        ...base,
        verdict: prior.verdict,
        status: staged ? ("staged" as const) : base.status,
        verification: staged ? prior.verification : base.verification,
      };
    }
    if (prior?.status === "staged" && base.status === "open") {
      return { ...base, status: "staged" as const, verification: prior.verification };
    }
    return base;
  });
  const leftovers = previous
    .filter((item) => !fresh.some((finding) => finding.id === item.id))
    .map((item) => ({ ...item, status: "fixed" as const, updatedAt: new Date().toISOString() }));
  return [...fresh, ...leftovers];
}

export function saveScan(root: string, findings: Finding[]): StoreData {
  const current = loadStore(root);
  const investigations = current.findings.filter((finding) => finding.ruleId === "LLM-INVESTIGATION");
  const kept = investigations
    .filter((finding) => investigationStillValid(root, finding))
    .map((finding) => applyException(finding, current.exceptions));
  const now = new Date().toISOString();
  const stale = investigations
    .filter((finding) => !kept.some((item) => item.id === finding.id))
    .map((finding) => ({ ...finding, status: "fixed" as const, updatedAt: now }));
  const baseline = current.findings.filter((finding) => finding.ruleId !== "LLM-INVESTIGATION");
  const incoming = findings.filter((finding) => finding.ruleId !== "LLM-INVESTIGATION");
  const merged = mergeFindings(baseline, incoming, current.exceptions);
  const ids = new Set(merged.map((finding) => finding.id));
  const combined = [...merged, ...kept.filter((finding) => !ids.has(finding.id)), ...stale.filter((finding) => !ids.has(finding.id))];
  const active = new Set(combined.filter((finding) => finding.status !== "fixed").map((finding) => finding.id));
  const data: StoreData = {
    ...current,
    findings: combined,
    staged: current.staged.filter((stage) => active.has(stage.findingId)),
  };
  saveStore(root, data);
  return data;
}

const CATEGORIES = new Set<Category>([
  "authentication",
  "authorization",
  "storage",
  "cryptography",
  "network",
  "platform",
  "webview",
  "injection",
  "privacy",
  "build",
  "dependencies",
  "resilience",
]);

export function recordInvestigation(
  root: string,
  input: { file: string; line: string; title: string; why: string; recommendation: string; category: string; severity: string; masvs?: string },
): Finding {
  const relative = input.file.replace(/\\/g, "/").replace(/^\.\//, "");
  if (!relative || relative.split("/").includes("..")) throw new Error("Investigation file must stay inside the repository.");
  const real = containedRealpath(root, relative);
  if (!real) throw new Error(`File is outside the repository or missing: ${relative}`);
  const lineNo = Number(input.line);
  if (!Number.isInteger(lineNo) || lineNo < 1) throw new Error("Investigation needs a real line number.");
  const source = fs.readFileSync(real, "utf8");
  const lineText = source.split(/\r?\n/)[lineNo - 1];
  if (!lineText || lineText.trim().length === 0) throw new Error("That line is empty or past the end of the file.");
  if (input.title.trim().length < 8 || input.why.trim().length < 12 || input.recommendation.trim().length < 12) {
    throw new Error("A model finding needs a title, why, and recommendation grounded in the line you read.");
  }
  if (!CATEGORIES.has(input.category as Category)) throw new Error("Unknown category.");
  const allowed: Severity[] = ["P1", "P2", "P3", "informational"];
  if (!allowed.includes(input.severity as Severity)) {
    throw new Error("Model investigations cannot be P0. Use P1, P2, P3, or informational. Confidence stays medium.");
  }
  const language = languageOf(relative);
  if (!language) throw new Error("Investigation file is not a supported Android source file.");
  const redacted = redact(lineText).trim().slice(0, 240);
  const masvs = masvsForInvestigation(input.masvs);
  const finding = toFinding(
    {
      ruleId: "LLM-INVESTIGATION",
      title: input.title.trim(),
      language,
      path: relative,
      line: lineNo,
      severity: input.severity as Severity,
      confidence: "medium",
      category: input.category as Category,
      detectionMethods: ["llm-investigation"],
      evidence: [{ path: relative, line: lineNo, description: `Recorded from source: ${redacted}` }],
      attackScenario: "This line is in the app only if that code is reached. The model did not confirm a vulnerable path.",
      preconditions: ["The recorded line is still present and is part of the shipped app."],
      why: input.why.trim(),
      recommendation: input.recommendation.trim(),
      recipe: "manual",
      masvs,
      fingerprintSource: sha256(redact(lineText)).slice(0, 16),
    },
    new Date().toISOString(),
    collectFiles(root).files,
  );
  const data = loadStore(root);
  data.findings = [...data.findings.filter((item) => item.id !== finding.id), finding];
  saveStore(root, data);
  return finding;
}

function masvsForInvestigation(requested: string | undefined): string[] {
  const fallback = requirementIds("LLM-INVESTIGATION");
  if (!requested?.trim()) return fallback;
  const ids = requested.split(/[,\s]+/).filter(Boolean);
  const allowed = new Set<string>(MASVS_REQUIREMENTS);
  if (ids.length === 0 || ids.some((id) => !allowed.has(id))) throw new Error("MASVS id is not a known requirement.");
  return ids;
}

function investigationStillValid(root: string, finding: Finding): boolean {
  const real = containedRealpath(root, finding.path);
  if (!real) return false;
  const lineText = fs.readFileSync(real, "utf8").split(/\r?\n/)[finding.line - 1];
  if (lineText === undefined) return false;
  const source = sha256(redact(lineText)).slice(0, 16);
  return finding.fingerprint === fingerprintOf(["LLM-INVESTIGATION", finding.path, source]);
}

function requireFinding(data: StoreData, findingId: string): Finding {
  const finding = data.findings.find((item) => item.id === findingId);
  if (!finding) throw new Error(`Unknown finding: ${findingId}`);
  return finding;
}

function readProjectFile(root: string, relativePath: string): string {
  const real = containedRealpath(root, relativePath);
  if (!real) throw new Error(`File is outside the repository or missing: ${relativePath}`);
  return fs.readFileSync(real, "utf8");
}

function projectFiles(root: string): { path: string; text: string }[] {
  return collectFiles(root).files;
}

export function stageFix(root: string, findingId: string): StagedChange {
  const data = loadStore(root);
  const finding = requireFinding(data, findingId);
  const before = readProjectFile(root, finding.path);
  const proposal = proposePatch(finding, before);
  const review = reviewChange(finding, before, proposal.after, projectFiles(root));
  const checks: Verification["checks"] = proposal.after
    ? [
        {
          name: "deterministic-rules",
          status: review.decision === "blocked" ? "failed" : "passed",
          detail:
            review.decision === "blocked"
              ? review.reasons.join(" ")
              : "The staged file no longer matches the original check. This does not by itself prove the issue is resolved.",
        },
        {
          name: "build-and-tests",
          status: "not-run",
          detail: "Build and unit tests were not executed. SecureDroid does not run repository build scripts.",
        },
      ]
    : [{ name: "deterministic-rules", status: "not-run", detail: "No source patch was generated." }];
  const status: Verification["status"] =
    review.decision === "blocked" ? "blocked" : proposal.after ? "partial" : "not-run";
  const stage: StagedChange = {
    findingId,
    path: finding.path,
    baseHash: sha256(before),
    recipe: finding.recipe,
    kind: proposal.kind,
    diff: proposal.after ? unifiedDiff(finding.path, before, proposal.after) : proposal.note,
    patched: proposal.after,
    review,
    verification: { status, checks },
    createdAt: new Date().toISOString(),
  };
  finding.status = "staged";
  finding.verification = stage.verification;
  finding.updatedAt = stage.createdAt;
  data.staged = [stage, ...data.staged.filter((item) => item.findingId !== findingId)];
  saveStore(root, data);
  return stage;
}

export function verifyStaged(root: string, findingId: string): StagedChange {
  const data = loadStore(root);
  const stage = data.staged.find((item) => item.findingId === findingId);
  if (!stage) throw new Error(`No staged change for ${findingId}`);
  const current = readProjectFile(root, stage.path);
  if (sha256(current) !== stage.baseHash) {
    stage.review = { decision: "blocked", reasons: ["The file changed after the patch was staged. Reject it and stage a new one."] };
    stage.verification = {
      status: "blocked",
      checks: [{ name: "stale-file", status: "blocked", detail: stage.review.reasons[0] ?? "Stale file." }],
    };
  } else if (!stage.patched) {
    stage.verification = {
      status: "not-run",
      checks: [{ name: "deterministic-rules", status: "not-run", detail: "No source patch was generated." }],
    };
  } else {
    const finding = requireFinding(data, findingId);
    const files = projectFiles(root).map((file) => (file.path === stage.path ? { path: file.path, text: stage.patched ?? file.text } : file));
    stage.review = reviewChange(finding, current, stage.patched, files);
    stage.verification = {
      status: stage.review.decision === "blocked" ? "blocked" : "partial",
      checks: [
        {
          name: "deterministic-rules",
          status: stage.review.decision === "blocked" ? "failed" : "passed",
          detail: stage.review.reasons.join(" ") || "The staged file no longer matches the original check.",
        },
        {
          name: "build-and-tests",
          status: "not-run",
          detail: "Build and unit tests were not executed.",
        },
      ],
    };
  }
  const finding = data.findings.find((item) => item.id === findingId);
  if (finding) finding.verification = stage.verification;
  saveStore(root, data);
  return stage;
}

export function acceptStaged(root: string, findingId: string): Finding {
  const data = loadStore(root);
  const stage = data.staged.find((item) => item.findingId === findingId);
  if (!stage) throw new Error(`No staged change for ${findingId}`);
  if (!stage.patched || stage.kind !== "patch" || stage.review.decision === "recommendation-only") {
    throw new Error("This finding has a recommendation, not a patch that can be saved.");
  }
  if (stage.review.decision === "blocked" || stage.verification.status === "blocked" || stage.verification.status === "failed") {
    throw new Error(`Refusing to save a ${stage.review.decision} change. ${stage.review.reasons.join(" ")}`);
  }
  const real = containedRealpath(root, stage.path);
  if (!real) throw new Error("The original file is missing.");
  const current = fs.readFileSync(real, "utf8");
  if (sha256(current) !== stage.baseHash) {
    throw new Error("The file changed after the patch was staged. The patch was not saved.");
  }
  const finding = requireFinding(data, findingId);
  if (finding.status === "staged") finding.status = "open";
  fs.writeFileSync(real, stage.patched);
  data.staged = data.staged.filter((item) => item.findingId !== findingId);
  saveStore(root, data);
  const rescanned = saveScan(root, evaluateRepository(root).findings);
  const updated = rescanned.findings.find((item) => item.id === findingId);
  if (!updated) throw new Error("The finding was not recorded after saving the patch.");
  return updated;
}

export function rejectStaged(root: string, findingId: string): Finding {
  const data = loadStore(root);
  const finding = requireFinding(data, findingId);
  data.staged = data.staged.filter((item) => item.findingId !== findingId);
  if (finding.status === "staged") finding.status = "open";
  finding.updatedAt = new Date().toISOString();
  saveStore(root, data);
  return finding;
}

export function acceptException(root: string, findingId: string, reason: string, reviewer?: string): ExceptionRecord {
  const trimmed = reason.trim();
  if (trimmed.length < 8) throw new Error("An exception needs a reason of at least 8 characters.");
  const data = loadStore(root);
  const finding = requireFinding(data, findingId);
  const record: ExceptionRecord = {
    findingId: finding.id,
    ruleId: finding.ruleId,
    path: finding.path,
    fingerprint: finding.fingerprint,
    reason: trimmed,
    createdAt: new Date().toISOString(),
    reviewer,
  };
  data.exceptions = [record, ...data.exceptions.filter((item) => item.findingId !== finding.id)];
  finding.status = "suppressed";
  finding.updatedAt = record.createdAt;
  saveStore(root, data);
  return record;
}
