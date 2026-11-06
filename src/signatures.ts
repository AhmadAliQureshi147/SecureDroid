import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { STANDARDS } from "./standards.ts";
import type { SourceFile } from "./types.ts";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

export interface SignatureHit {
  engine: "sigma" | "yara";
  ruleId: string;
  path: string;
  line: number;
  message: string;
}

interface CompiledRule {
  engine: "sigma" | "yara";
  ruleId: string;
  message: string;
  patterns: RegExp[];
}

let compiled: CompiledRule[] | undefined;

export function signatureHits(files: SourceFile[]): SignatureHit[] {
  const rules = loadRules();
  const hits: SignatureHit[] = [];
  for (const file of files) {
    for (const rule of rules) {
      for (const pattern of rule.patterns) {
        pattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(file.text))) {
          const line = file.text.slice(0, match.index).split(/\r?\n/).length;
          const row = file.text.split(/\r?\n/)[line - 1] ?? "";
          if (commented(row)) {
            if (match[0].length === 0) pattern.lastIndex += 1;
            continue;
          }
          if (rule.ruleId === "PLATFORM-MUTABLE-PENDING-INTENT" && /FLAG_IMMUTABLE/.test(file.text.slice(match.index, match.index + 350))) {
            if (match[0].length === 0) pattern.lastIndex += 1;
            continue;
          }
          if (!hits.some((hit) => hit.engine === rule.engine && hit.ruleId === rule.ruleId && hit.path === file.path && hit.line === line)) {
            hits.push({ engine: rule.engine, ruleId: rule.ruleId, path: file.path, line, message: rule.message });
          }
          break;
        }
      }
    }
  }
  return hits;
}

function loadRules(): CompiledRule[] {
  if (compiled) return compiled;
  const rules = [...loadSigma(), ...loadYara()];
  if (!rules.some((rule) => rule.engine === "sigma") || !rules.some((rule) => rule.engine === "yara")) {
    throw new Error("engines/sigma and engines/yara must both contain rules");
  }
  compiled = rules;
  return rules;
}

function loadSigma(): CompiledRule[] {
  const directory = path.join(ROOT, "engines", "sigma");
  return fs.readdirSync(directory).filter((name) => name.endsWith(".yml")).flatMap((name) => parseSigma(fs.readFileSync(path.join(directory, name), "utf8"), name));
}

function loadYara(): CompiledRule[] {
  const directory = path.join(ROOT, "engines", "yara");
  return fs.readdirSync(directory).filter((name) => name.endsWith(".yar")).flatMap((name) => parseYara(fs.readFileSync(path.join(directory, name), "utf8"), name));
}

function parseSigma(text: string, fileName: string): CompiledRule[] {
  const rules: CompiledRule[] = [];
  for (const document of text.split(/\n---\n/)) {
    const tag = /securedroid\.([A-Z0-9-]+)/.exec(document);
    if (!tag?.[1]) continue;
    const ruleId = tag[1];
    assertRule(ruleId, fileName);
    const description = /^description:\s*(.+)$/m.exec(document)?.[1]?.trim() || STANDARDS[ruleId]?.summary || ruleId;
    const patterns = [...document.matchAll(/^\s+-\s+'([^']*(?:''[^']*)*)'/gm)].map((item) => item[1] ?? "").filter(Boolean);
    if (patterns.length === 0) throw new Error(`${fileName} rule ${ruleId} has no patterns`);
    rules.push({
      engine: "sigma",
      ruleId,
      message: description,
      patterns: patterns.map((pattern) => new RegExp(pattern.replace(/''/g, "'"), "g")),
    });
  }
  if (rules.length === 0) throw new Error(`${fileName} has no Sigma rules`);
  return rules;
}

function parseYara(text: string, fileName: string): CompiledRule[] {
  const rules: CompiledRule[] = [];
  for (const chunk of text.split(/\n(?=rule\s+)/)) {
    if (!chunk.trim().startsWith("rule ")) continue;
    const ruleId = /rule_id\s*=\s*"([A-Z0-9-]+)"/.exec(chunk)?.[1];
    if (!ruleId) throw new Error(`${fileName} has a YARA rule without rule_id`);
    assertRule(ruleId, fileName);
    const description = /description\s*=\s*"([^"]*)"/.exec(chunk)?.[1] || STANDARDS[ruleId]?.summary || ruleId;
    const strings = /strings:\s*([\s\S]*?)\n\s*condition:/.exec(chunk)?.[1] ?? "";
    const patterns = [
      ...[...strings.matchAll(/\/((?:\\\/|[^/\n])*)\/[a-z]*/g)].map((item) => yaraToJs(item[1] ?? "")),
      ...[...strings.matchAll(/=\s*"((?:\\"|[^"\n])*)"/g)].map((item) => escapeRegExp(item[1] ?? "").replace(/\\"/g, '"')),
    ].filter(Boolean);
    if (patterns.length === 0) throw new Error(`${fileName} rule ${ruleId} has no strings`);
    rules.push({
      engine: "yara",
      ruleId,
      message: description,
      patterns: patterns.map((pattern) => new RegExp(pattern, "g")),
    });
  }
  if (rules.length === 0) throw new Error(`${fileName} has no YARA rules`);
  return rules;
}

function yaraToJs(pattern: string): string {
  return pattern.replace(/\[\[:space:\]\]/g, "\\s").replace(/\\\//g, "/");
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function assertRule(ruleId: string, fileName: string): void {
  if (!STANDARDS[ruleId] || ruleId === "LLM-INVESTIGATION") {
    throw new Error(`${fileName} uses unknown rule ${ruleId}`);
  }
}

function commented(snippet: string): boolean {
  const trimmed = snippet.trim();
  return trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("#") || trimmed.startsWith("--") || trimmed.startsWith("<!--");
}
