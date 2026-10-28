import { evaluateRepository } from "./analysis.ts";
import { collectExternalFindings, mergeExternal } from "./engines.ts";
import { saveScan, acceptException, acceptStaged, loadStore, recordInvestigation, rejectStaged, stageFix, verifyStaged } from "./store.ts";
import { judgeFinding, triageRepository } from "./triage.ts";
import type { Finding, Severity } from "./types.ts";

const RANK: Record<Severity, number> = { P0: 0, P1: 1, P2: 2, P3: 3, informational: 4 };

export interface ActionRequest {
  action: string;
  root: string;
  findingId?: string;
  reason?: string;
  file?: string;
  line?: string;
  title?: string;
  why?: string;
  recommendation?: string;
  category?: string;
  severity?: string;
  masvs?: string;
  decision?: string;
}

export interface ActionResult {
  ok: boolean;
  text: string;
  data?: unknown;
}

const PROCEDURE = [
  "SecureDroid procedure:",
  "1. Use the detect and map results before judging a file in isolation.",
  "2. Treat scan findings as candidates with the confidence already assigned. Do not raise a finding to confirmed without source evidence.",
  "3. Read the evidence paths. A suspicious API is not a vulnerability until the surrounding code fails to constrain it.",
  "4. JavaScript enabled on a WebView, Compose state, and a launcher activity are not findings by themselves.",
  "5. Read each finding's runtime field before describing what a running app exposes. Do not write exploit steps.",
  "6. Stage a fix with the fix action, or stage every automatic recipe with remediate. Do not write the source file yourself.",
  "7. The developer accepts or rejects each staged patch. remediate does not accept anything.",
  "8. partial verification means the static check cleared and the build was not run. Do not call that a pass.",
  "9. Record an extra finding with the record action only when you can name a real file and line. It stays medium confidence and cannot be P0.",
  "10. Report only findings the verifier upheld. Withheld findings are candidates, not vulnerabilities. Spawn android-verifier before telling the developer something is vulnerable.",
].join("\n");

function bySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => RANK[a.severity] - RANK[b.severity] || a.path.localeCompare(b.path));
}

function counts(findings: Finding[]): string {
  const open = findings.filter((finding) => finding.status === "open" || finding.status === "staged");
  const parts = ["P0", "P1", "P2", "P3", "informational"].map((severity) => {
    const count = open.filter((finding) => finding.severity === severity).length;
    return `${severity}=${count}`;
  });
  return parts.join(" ");
}

function formatFinding(finding: Finding): string {
  const evidence = finding.evidence.map((item) => `  - ${item.path}:${item.line} ${item.description}`).join("\n");
  return [
    `${finding.severity} ${finding.confidence} ${finding.status} ${finding.ruleId}`,
    finding.title,
    `${finding.path}:${finding.line} [${finding.language}] ${finding.id}`,
    `Why: ${finding.why}`,
    `Scenario: ${finding.attackScenario}`,
    `Preconditions: ${finding.preconditions.join("; ")}`,
    `Recommendation: ${finding.recommendation}`,
    finding.runtime
      ? `Runtime: ${finding.runtime.exposure}. ${finding.runtime.summary}`
      : "Runtime: unknown until the next scan.",
    `Recipe: ${finding.recipe}. MASVS: ${finding.masvs.join(", ")}`,
    finding.verdict ? `Verifier: ${finding.verdict.result}. ${finding.verdict.reason}` : "Verifier: not run.",
    `Verification: ${finding.verification.status}`,
    "Evidence:",
    evidence,
  ].join("\n");
}

function formatList(findings: Finding[]): string {
  if (findings.length === 0) return "No findings.";
  return bySeverity(findings).map(formatFinding).join("\n\n");
}

function reportFindings(findings: Finding[]): string {
  const active = findings.filter((finding) => finding.status === "open" || finding.status === "staged");
  const upheld = active.filter((finding) => finding.verdict?.result === "upheld");
  const withheld = active.filter((finding) => finding.verdict?.result !== "upheld");
  const withheldLines = withheld.map((finding) => `- ${finding.status} ${finding.severity} ${finding.confidence} ${finding.runtime?.exposure ?? "unknown"} ${finding.ruleId} ${finding.path}:${finding.line}`).join("\n");
  return [
    `Verified vulnerabilities: ${counts(upheld)}`,
    formatList(upheld),
    "",
    `Withheld ${withheld.length}. These are not reported as vulnerabilities.`,
    withheldLines || "- none",
  ].join("\n");
}

function persistScan(root: string, findings: Finding[]): string[] {
  const external = collectExternalFindings(root);
  saveScan(root, mergeExternal(findings, external.findings));
  return external.notes;
}

export function runSecureDroid(request: ActionRequest): ActionResult {
  try {
    const root = request.root;
    if (request.action === "detect" || request.action === "map" || request.action === "scan" || request.action === "review") {
      const evaluated = evaluateRepository(root);
      const notes = request.action === "scan" || request.action === "review" ? persistScan(root, evaluated.findings) : [];
      const header = [
        `Android project: ${evaluated.detection.isAndroid ? "yes" : "no"}`,
        `Frameworks: ${evaluated.detection.frameworks.join(", ") || "none"}`,
        `Languages: ${evaluated.detection.languages.join(", ") || "none"}`,
        `Modules: ${evaluated.detection.modules.join(", ") || "none"}`,
        `Files: ${evaluated.map.filesScanned}`,
        `Tools: ${Object.entries(evaluated.detection.tools).map(([name, present]) => `${name}=${present ? "installed" : "missing"}`).join(", ")}`,
        ...evaluated.detection.limitations.map((item) => `Limitation: ${item}`),
        ...notes.map((item) => `External: ${item}`),
      ];
      if (request.action === "detect") {
        return { ok: true, text: header.join("\n"), data: evaluated.detection };
      }
      const entries = evaluated.map.entryPoints
        .map((entry) => `- ${entry.kind} ${entry.name} exported=${String(entry.exported)} ${entry.path}:${entry.line}`)
        .join("\n");
      if (request.action === "map") {
        return {
          ok: true,
          text: `${header.join("\n")}\nEntry points:\n${entries || "- none"}`,
          data: evaluated.map,
        };
      }
      const stored = request.action === "scan" || request.action === "review" ? triageRepository(root) : loadStore(root).findings;
      const body = `${header.join("\n")}\n${reportFindings(stored)}`;
      if (request.action === "review") {
        return { ok: true, text: `${PROCEDURE}\n\n${body}`, data: { findings: stored, procedure: PROCEDURE } };
      }
      return { ok: true, text: body, data: stored };
    }

    if (request.action === "status" || request.action === "findings" || request.action === "triage") {
      triageRepository(root);
      const stored = loadStore(root);
      return { ok: true, text: reportFindings(stored.findings), data: stored };
    }

    if (request.action === "record") {
      const finding = recordInvestigation(root, {
        file: request.file ?? "",
        line: request.line ?? "",
        title: request.title ?? "",
        why: request.why ?? "",
        recommendation: request.recommendation ?? "",
        category: request.category ?? "",
        severity: request.severity ?? "",
        masvs: request.masvs,
      });
      return {
        ok: true,
        text: `Recorded a medium-confidence investigation. It is not confirmed.\n\n${formatFinding(finding)}`,
        data: finding,
      };
    }

    if (request.action === "remediate") {
      const evaluated = evaluateRepository(root);
      persistScan(root, evaluated.findings);
      const open = loadStore(root).findings.filter((finding) => finding.status === "open");
      const automatic = open.filter((finding) => finding.recipe === "automatic");
      const manual = open.filter((finding) => finding.recipe !== "automatic");
      const staged = automatic.map((finding) => stageFix(root, finding.id));
      const stagedText = staged.map((stage) => `- ${stage.findingId} ${stage.review.decision} verification=${stage.verification.status}`).join("\n");
      const manualText = manual.map((finding) => `- ${finding.severity} ${finding.ruleId} ${finding.path}:${finding.line}`).join("\n");
      return {
        ok: true,
        text: [
          `Staged ${staged.length} automatic fix${staged.length === 1 ? "" : "es"}. Source files were not modified.`,
          stagedText || "- none",
          "Manual findings still need a reviewed change:",
          manualText || "- none",
          "The developer accepts or rejects each stage. This action does not accept patches.",
        ].join("\n"),
        data: { staged, manual },
      };
    }

    if (request.action === "judge") {
      const finding = judgeFinding(root, request.findingId?.trim() ?? "", request.decision ?? "", request.file ?? "", request.line ?? "", request.why ?? request.reason ?? "");
      return {
        ok: true,
        text: `Verifier ${finding.verdict?.result} for ${finding.id}. Confidence stays ${finding.confidence}.\n\n${formatFinding(finding)}`,
        data: finding,
      };
    }

    const findingId = request.findingId?.trim();
    if (!findingId) return { ok: false, text: "This action needs a finding id." };

    if (request.action === "investigate" || request.action === "explain" || request.action === "recommend") {
      const evaluated = evaluateRepository(root);
      persistScan(root, evaluated.findings);
      const finding = loadStore(root).findings.find((item) => item.id === findingId);
      if (!finding) return { ok: false, text: `Unknown finding: ${findingId}` };
      if (request.action === "recommend") {
        return {
          ok: true,
          text: `${finding.recommendation}\nRecipe: ${finding.recipe}.\nStage the change with the fix action. Do not write the source file directly.`,
          data: finding,
        };
      }
      const note =
        request.action === "investigate"
          ? "Confidence was assigned from source evidence. Read the evidence files before describing exploitability. Do not invent a line, a permission, or a test result."
          : "Explain only what the evidence supports.";
      return { ok: true, text: `${note}\n\n${formatFinding(finding)}`, data: finding };
    }

    if (request.action === "fix") {
      const stage = stageFix(root, findingId);
      return {
        ok: true,
        text: [
          `Staged ${stage.kind} for ${findingId}`,
          `Review: ${stage.review.decision}`,
          stage.review.reasons.map((reason) => `- ${reason}`).join("\n"),
          `Verification: ${stage.verification.status}`,
          stage.verification.checks.map((check) => `- ${check.name}: ${check.status} ${check.detail}`).join("\n"),
          "Diff:",
          stage.diff,
          "The source file was not modified. The developer accepts or rejects this stage.",
        ].join("\n"),
        data: stage,
      };
    }

    if (request.action === "verify") {
      const stage = verifyStaged(root, findingId);
      return {
        ok: true,
        text: `Verification ${stage.verification.status}\n${stage.verification.checks.map((check) => `- ${check.name}: ${check.status} ${check.detail}`).join("\n")}`,
        data: stage,
      };
    }

    if (request.action === "accept") {
      const finding = acceptStaged(root, findingId);
      return { ok: true, text: `Saved. Finding status is now ${finding.status}.\n${formatFinding(finding)}`, data: finding };
    }

    if (request.action === "reject") {
      const finding = rejectStaged(root, findingId);
      return { ok: true, text: `Rejected the staged change. Source was left unchanged. Status: ${finding.status}.`, data: finding };
    }

    if (request.action === "except") {
      const record = acceptException(root, findingId, request.reason ?? "");
      return {
        ok: true,
        text: `Exception recorded for this fingerprint only. A later code change that alters the evidence will open the finding again.\nReason: ${record.reason}`,
        data: record,
      };
    }

    return { ok: false, text: `Unknown action: ${request.action}` };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { ok: false, text: message };
  }
}
