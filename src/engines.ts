import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { collectFiles, toFinding } from "./analysis.ts";
import { languageOf } from "./detect.ts";
import { ruleStillMatches } from "./rules.ts";
import { STANDARDS, requirementIds } from "./standards.ts";
import { resolveTool, toolEnv } from "./tools.ts";
import type { Category, Finding, SourceFile } from "./types.ts";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

interface ToolHit {
  ruleId: string;
  path: string;
  line: number;
  message: string;
}

export function collectExternalFindings(projectRoot: string): { findings: Finding[]; notes: string[] } {
  const files = collectFiles(projectRoot).files;
  const notes: string[] = [];
  const findings: Finding[] = [];
  const semgrep = resolveTool("semgrep");
  if (!semgrep) notes.push("semgrep is not installed. The built-in rules still ran.");
  else notes.push(runPack(findings, "semgrep", semgrep, ["--config", path.join(ROOT, "engines", "semgrep"), "--json", "--quiet", "--metrics", "off", "--disable-version-check", projectRoot], projectRoot, files));
  const astGrep = resolveTool("ast-grep");
  if (!astGrep) notes.push("ast-grep is not installed. Structural checks use SecureDroid patterns.");
  else notes.push(runPack(findings, "ast-grep", astGrep, ["scan", "--json=compact", "-c", path.join(ROOT, "engines", "ast-grep", "sgconfig.yml"), projectRoot], projectRoot, files));
  return { findings, notes };
}

export function findingsFromSemgrep(stdout: string, projectRoot = "", files: SourceFile[] = []): Finding[] {
  return confirmHits(parseSemgrep(stdout), projectRoot, files, "semgrep");
}

export function findingsFromAstGrep(stdout: string, projectRoot = "", files: SourceFile[] = []): Finding[] {
  return confirmHits(parseAstGrep(stdout), projectRoot, files, "ast-grep");
}

export function mergeExternal(primary: Finding[], extra: Finding[]): Finding[] {
  const merged = primary.map((finding) => ({ ...finding, detectionMethods: [...finding.detectionMethods], evidence: [...finding.evidence] }));
  const added: Finding[] = [];
  for (const item of extra) {
    const existing = merged.find((finding) => finding.ruleId === item.ruleId && finding.path === item.path);
    if (existing) {
      for (const method of item.detectionMethods) {
        if (!existing.detectionMethods.includes(method)) existing.detectionMethods.push(method);
      }
      if (!existing.evidence.some((evidence) => evidence.description === item.evidence[0]?.description)) {
        existing.evidence.push(...item.evidence);
      }
      continue;
    }
    added.push(item);
  }
  return [...merged, ...added];
}

function runPack(findings: Finding[], engine: "semgrep" | "ast-grep", binary: string, args: string[], projectRoot: string, files: SourceFile[]): string {
  const result = spawnSync(binary, args, {
    encoding: "utf8",
    timeout: 45_000,
    killSignal: "SIGKILL",
    env: toolEnv(),
  });
  const stdout = result.stdout ?? "";
  if (!stdout.trim()) return `${engine} did not return results. The built-in rules still ran.`;
  const hits = engine === "semgrep" ? parseSemgrep(stdout) : parseAstGrep(stdout);
  const kept = confirmHits(hits, projectRoot, files, engine);
  findings.push(...kept);
  const dropped = hits.length - kept.length;
  return `${engine}: ${kept.length} confirmed, ${dropped} dropped because the source line did not show the pattern.`;
}

const LINE_PATTERNS: Record<string, RegExp> = {
  "STORAGE-WORLD-ACCESSIBLE": /MODE_WORLD_(?:READABLE|WRITEABLE)|openFileOutput\s*\([^,\n]*,\s*[12]\s*\)|getSharedPreferences\s*\([^,\n]*,\s*[12]\s*\)/,
  "NETWORK-SSL-ERROR-PROCEED": /proceed\s*\(/,
  "CRYPTO-ECB": /ECB|Cipher\.getInstance\(\s*"AES"\s*\)/,
  "CRYPTO-WEAK-ALGORITHM": /(?:DESede|DES|RC2|RC4|Blowfish|PBEWithMD5)/,
  "CRYPTO-STATIC-SEED": /SecureRandom[\s\S]{0,180}setSeed\s*\(\s*(?:\d+|["'])/,
  "WEBVIEW-DEBUG": /setWebContentsDebuggingEnabled\s*\(\s*true\s*\)/,
  "FLUTTER-BAD-CERTIFICATE": /badCertificateCallback[\s\S]{0,120}true/,
  "NETWORK-MIXED-CONTENT": /MIXED_CONTENT_ALWAYS_ALLOW/,
  "PLATFORM-MUTABLE-PENDING-INTENT": /PendingIntent\.get(?:Activity|Service|Broadcast)/,
  "NETWORK-WEAK-TLS": /SSLContext\.getInstance\(\s*"(?:SSL|SSLv3|TLSv1|TLSv1\.1)"|setEnabledProtocols[\s\S]{0,160}(?:SSLv3|SSL|TLSv1\.1|TLSv1)(?![.\w])/,
  "PLATFORM-PARSE-URI": /URI_(?:ALLOW_UNSAFE|INTENT_SCHEME)/,
  "CODE-DYNAMIC-LOAD": /(?:DexClassLoader|InMemoryDexClassLoader|PathClassLoader|BaseDexClassLoader)\s*\(/,
  "CODE-PACKAGE-CONTEXT": /CONTEXT_(?:IGNORE_SECURITY|INCLUDE_CODE)/,
  "CODE-NATIVE-LOAD": /System\.load\s*\(/,
  "CODE-NATIVE-UNSAFE": /\b(?:gets|strcpy|strcat|sprintf|vsprintf|mktemp)\s*\(/,
  "CODE-NATIVE-EXEC": /\b(?:system|popen)\s*\(/,
  "NETWORK-DOTNET-TRUST-ALL": /ServerCertificate(?:CustomValidationCallback|ValidationCallback)/,
  "NETWORK-PYTHON-UNVERIFIED": /verify\s*=\s*False|_create_unverified_context\s*\(/,
  "CODE-PYTHON-PICKLE": /pickle\.loads\s*\(/,
  "NETWORK-RUST-INVALID-CERTS": /danger_accept_invalid_certs\s*\(\s*true\s*\)/,
  "NETWORK-RUBY-VERIFY-NONE": /VERIFY_NONE/,
  "CODE-LUA-DYNAMIC": /\bos\.execute\s*\(|\bloadstring\s*\(/,
  "PLATFORM-TASK-REPARENT": /android:allowTaskReparenting\s*=\s*"true"/,
  "PRIVACY-HTTP-BODY": /HttpLoggingInterceptor\.Level\.BODY/,
  "WEBVIEW-SAFE-BROWSING": /setSafeBrowsingEnabled\s*\(\s*false\s*\)/,
  "STORAGE-PROVIDER-PATH": /<root-path\b|path\s*=\s*"\/"/,
  "PLATFORM-SHARED-USER-ID": /android:sharedUserId\s*=/,
};

export function lineConfirms(ruleId: string, file: SourceFile, line: number): boolean {
  if (ruleId === "NETWORK-TRUST-ALL") return emptyTrustBody(file.text, line);
  if (ruleId === "WEBVIEW-DEBUG") {
    const at = file.text.search(/setWebContentsDebuggingEnabled\s*\(\s*true\s*\)/);
    if (at >= 0 && /BuildConfig\.DEBUG/.test(file.text.slice(Math.max(0, at - 160), at))) return false;
  }
  const pattern = LINE_PATTERNS[ruleId];
  if (!pattern) return false;
  const rows = file.text.split(/\r?\n/);
  return pattern.test(rows.slice(Math.max(0, line - 3), line + 3).join("\n"));
}

function emptyTrustBody(text: string, line: number): boolean {
  const rows = text.split(/\r?\n/);
  const slice = rows.slice(Math.max(0, line - 6), line + 8).join("\n");
  const match = /checkServerTrusted\s*\([^)]*\)\s*\{([^{}]*)\}/.exec(slice);
  if (!match) return false;
  const body = (match[1] ?? "").replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "").trim();
  return body.length === 0;
}


function confirmHits(hits: ToolHit[], projectRoot: string, files: SourceFile[], engine: "semgrep" | "ast-grep"): Finding[] {
  const now = new Date().toISOString();
  const findings: Finding[] = [];
  for (const hit of hits) {
    const relative = projectPath(projectRoot, hit.path);
    if (!relative) continue;
    const file = files.find((item) => item.path === relative);
    const builtin = Boolean(file && ruleStillMatches(hit.ruleId, file, files));
    const extra = Boolean(file && !builtin && lineConfirms(hit.ruleId, file, hit.line));
    if (!file || (!builtin && !extra)) continue;
    findings.push(
      toFinding(
        {
          ruleId: hit.ruleId,
          title: hit.message || STANDARDS[hit.ruleId]?.summary || hit.ruleId,
          language: languageOf(relative) ?? "kotlin",
          path: relative,
          line: hit.line,
          severity: "P2",
          confidence: "medium",
          category: categoryFor(hit.ruleId),
          detectionMethods: ["pattern"],
          evidence: [{ path: relative, line: hit.line, description: builtin ? `${engine} matched this rule, and the built-in rule still matches the file.` : `${engine} matched this line. The built-in file check missed it, and the line still shows the pattern.` }],
          attackScenario: "An open-source rule matched this source line. The built-in rule agrees the file still contains the issue.",
          preconditions: ["The matched code is part of the app that ships."],
          why: hit.message || STANDARDS[hit.ruleId]?.summary || "An external Android rule matched.",
          recommendation: "Confirm the match against the surrounding code, then stage a fix through SecureDroid.",
          recipe: "manual",
          masvs: requirementIds(hit.ruleId),
          fingerprintSource: `${engine}:${hit.ruleId}:${relative}:${hit.line}`,
        },
        now,
        files,
      ),
    );
  }
  return findings;
}

function parseSemgrep(stdout: string): ToolHit[] {
  let parsed: { results?: Array<{ check_id?: string; path?: string; start?: { line?: number }; extra?: { message?: string } }> };
  try {
    parsed = JSON.parse(stdout) as typeof parsed;
  } catch {
    return [];
  }
  const hits: ToolHit[] = [];
  for (const result of parsed.results ?? []) {
    const ruleId = ruleFromCheck(result.check_id ?? "");
    if (!ruleId || !result.path || !result.start?.line) continue;
    hits.push({ ruleId, path: result.path, line: result.start.line, message: result.extra?.message ?? "" });
  }
  return hits;
}

function parseAstGrep(stdout: string): ToolHit[] {
  const trimmed = stdout.trim();
  if (!trimmed) return [];
  try {
    return astHits(JSON.parse(trimmed) as unknown);
  } catch {
    return trimmed.split(/\r?\n/).flatMap((line) => {
      try {
        return astHits(JSON.parse(line) as unknown);
      } catch {
        return [];
      }
    });
  }
}

function astHits(value: unknown): ToolHit[] {
  const rows = Array.isArray(value) ? value : [value];
  const hits: ToolHit[] = [];
  for (const result of rows) {
    if (!result || typeof result !== "object") continue;
    const row = result as { ruleId?: string; file?: string; message?: string; range?: { start?: { line?: number } } };
    const ruleId = ruleFromCheck(row.ruleId ?? "");
    const line = row.range?.start?.line;
    if (!ruleId || !row.file || line === undefined) continue;
    hits.push({ ruleId, path: row.file, line: line + 1, message: row.message ?? "" });
  }
  return hits;
}

function ruleFromCheck(checkId: string): string | undefined {
  const parts = checkId.split(/[./]/).filter(Boolean);
  for (let index = parts.length - 1; index >= 0; index -= 1) {
    const candidate = parts[index];
    if (candidate && STANDARDS[candidate] && candidate !== "LLM-INVESTIGATION") return candidate;
  }
  return undefined;
}

function categoryFor(ruleId: string): Category {
  if (ruleId.startsWith("NETWORK") || ruleId.startsWith("FLUTTER-BAD")) return "network";
  if (ruleId.startsWith("CRYPTO") || ruleId.startsWith("SECRET") || ruleId.startsWith("BUILD-SIGNING")) return "cryptography";
  if (ruleId.startsWith("STORAGE") || ruleId.startsWith("ANDROID-BACKUP")) return "storage";
  if (ruleId.startsWith("WEBVIEW")) return "webview";
  if (ruleId.startsWith("INJECTION") || ruleId.startsWith("CODE-")) return "injection";
  if (ruleId.startsWith("PRIVACY")) return "privacy";
  if (ruleId.startsWith("ANDROID-DEBUG") || ruleId.startsWith("BUILD-RELEASE")) return "resilience";
  return "platform";
}

function projectPath(projectRoot: string, filePath: string): string | undefined {
  const normalized = filePath.replace(/\\/g, "/");
  if (normalized.split("/").includes("..")) return undefined;
  if (!projectRoot) {
    if (path.isAbsolute(filePath)) return undefined;
    return normalized.replace(/^\.\//, "");
  }
  const relative = path.relative(projectRoot, path.resolve(projectRoot, filePath));
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) return undefined;
  return relative.replace(/\\/g, "/");
}
