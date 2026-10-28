import { parseManifest } from "./manifest.ts";
import type { Confidence, SourceFile } from "./types.ts";

export type RuntimeExposure = "runtime-reachable" | "runtime-conditional" | "build-time";

export interface RuntimeAssessment {
  exposure: RuntimeExposure;
  summary: string;
}

const BUILD_RULES = new Set([
  "BUILD-SIGNING-SECRET",
  "BUILD-RELEASE-DEBUGGABLE",
  "STORAGE-LEGACY-EXTERNAL",
  "ANDROID-DEBUGGABLE",
  "ANDROID-BACKUP",
  "NETWORK-CLEARTEXT",
  "NETWORK-USER-CA",
  "PLATFORM-NORMAL-PERMISSION",
]);

const ENTRY_METHODS = new Set([
  "main",
  "onCreate",
  "onStart",
  "onResume",
  "onNewIntent",
  "onReceive",
  "onStartCommand",
  "onBind",
  "onHandleIntent",
  "query",
  "insert",
  "update",
  "delete",
  "call",
  "openFile",
  "getType",
]);

const SKIP_CALLS = new Set([
  "if",
  "for",
  "while",
  "when",
  "catch",
  "return",
  "super",
  "this",
  "Log",
  "require",
  "check",
  "error",
  "println",
  "print",
  "listOf",
  "mapOf",
  "setOf",
  "arrayOf",
  "TODO",
  "get",
  "set",
  "add",
  "put",
  "run",
  "open",
  "load",
  "init",
  "show",
  "hide",
  "send",
  "post",
  "create",
  "start",
  "stop",
]);

interface Span {
  name: string;
  startLine: number;
  body: string;
  lifecycle: boolean;
  react: boolean;
}

export function assessRuntime(
  ruleId: string,
  confidence: Confidence,
  location?: { path: string; line: number },
  files: SourceFile[] = [],
): RuntimeAssessment {
  if (ruleId === "ANDROID-EXPORTED-COMPONENT" || ruleId === "ANDROID-IMPLICIT-EXPORT") {
    if (confidence === "high" || confidence === "confirmed") {
      return {
        exposure: "runtime-reachable",
        summary: "This component is an entry point. Another app can start it while it stays enabled and exported.",
      };
    }
    return {
      exposure: "runtime-conditional",
      summary: "This component is only an entry point if no permission or authorization check stops the caller. That check is not confirmed.",
    };
  }
  if (BUILD_RULES.has(ruleId)) {
    return {
      exposure: "build-time",
      summary: "This is decided when the app is built. The resulting artifact keeps the setting or secret.",
    };
  }
  const file = location ? files.find((item) => item.path === location.path) : undefined;
  if (!file || !location) {
    return {
      exposure: "runtime-conditional",
      summary: "No call path from a launcher or exported component to this line was available.",
    };
  }
  if (reached(file, location.line, files)) {
    return {
      exposure: "runtime-reachable",
      summary: "A launcher or exported component reaches this line through the source that was scanned.",
    };
  }
  return {
    exposure: "runtime-conditional",
    summary: "No call path from a launcher or exported component reaches this line. It matters if some other code starts it.",
  };
}

interface IndexedSpan {
  key: string;
  body: string;
  file: SourceFile;
  span: Span;
}

function reached(file: SourceFile, line: number, files: SourceFile[]): boolean {
  const spans = indexSpans(files);
  const reachedKeys = new Set<string>();
  const reachedClasses = new Set<string>();
  const queue: IndexedSpan[] = [];
  for (const item of spans) {
    const entryFile = isEntryFile(item.file, files);
    if (item.span.name !== "main" && !item.span.react && !(entryFile && item.span.lifecycle)) continue;
    reachedKeys.add(item.key);
    queue.push(item);
  }
  const classOwners = new Map<string, string>();
  for (const item of files) {
    for (const name of declaredClasses(item.text)) classOwners.set(name, item.path);
  }
  while (queue.length > 0 && reachedKeys.size < 200) {
    const current = queue.shift();
    if (!current) break;
    for (const [name, ownerPath] of classOwners) {
      if (reachedClasses.has(name) || !usesClass(current.body, name)) continue;
      reachedClasses.add(name);
      for (const item of spans) {
        if (item.file.path !== ownerPath || reachedKeys.has(item.key)) continue;
        reachedKeys.add(item.key);
        queue.push(item);
      }
    }
    for (const item of spans) {
      if (reachedKeys.has(item.key) || item.span.name.length < 4 || SKIP_CALLS.has(item.span.name)) continue;
      if (!calls(current.body, item.span.name)) continue;
      reachedKeys.add(item.key);
      queue.push(item);
    }
  }
  const span = spans.find(
    (item) => item.file.path === file.path && item.span.startLine <= line && line < item.span.startLine + item.body.split("\n").length,
  );
  return span !== undefined && reachedKeys.has(span.key);
}

function indexSpans(files: SourceFile[]): IndexedSpan[] {
  const spans: IndexedSpan[] = [];
  for (const file of files) {
    for (const span of functionSpans(file.text)) {
      spans.push({ key: `${file.path}:${span.startLine}:${span.name}`, body: span.body, file, span });
    }
  }
  return spans;
}

function isEntryFile(file: SourceFile, files: SourceFile[]): boolean {
  const names = entryNames(files);
  if (declaredClasses(file.text).some((name) => names.has(name))) return true;
  return /\b(?:fun|void|function)\s+main\s*\(/.test(file.text) || /AppRegistry\.registerComponent/.test(file.text);
}

function entryNames(files: SourceFile[]): Set<string> {
  const names = new Set<string>();
  for (const file of files) {
    if (!file.path.endsWith("AndroidManifest.xml")) continue;
    for (const component of parseManifest(file.path, file.text).components) {
      if (component.exported === false) continue;
      const simple = component.name.split(".").pop() ?? "";
      if (simple && simple !== "(unnamed)") names.add(simple);
    }
  }
  return names;
}

function declaredClasses(text: string): string[] {
  return [...text.matchAll(/\b(?:class|object|interface)\s+([A-Za-z_][A-Za-z0-9_]*)/g)].map((match) => match[1] ?? "");
}

function functionSpans(text: string): Span[] {
  const lines = text.split(/\r?\n/);
  const starts: Array<{ name: string; line: number; lifecycle: boolean; react: boolean }> = [];
  lines.forEach((row, index) => {
    const name = definedName(row);
    if (!name) return;
    const previous = lines.slice(Math.max(0, index - 3), index).join("\n");
    starts.push({
      name,
      line: index + 1,
      lifecycle: ENTRY_METHODS.has(name),
      react: /@ReactMethod\b/.test(previous),
    });
  });
  return starts.map((item, index) => {
    const end = starts[index + 1]?.line ?? lines.length + 1;
    return {
      name: item.name,
      startLine: item.line,
      lifecycle: item.lifecycle,
      react: item.react,
      body: lines.slice(item.line - 1, end - 1).join("\n"),
    };
  });
}

function definedName(line: string): string | undefined {
  const fun = /\bfun\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/.exec(line);
  if (fun?.[1]) return fun[1];
  const fn = /\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/.exec(line);
  if (fn?.[1]) return fn[1];
  const typed = /\b(?:public|private|protected|internal|override|open|suspend|static|final)\s+(?:[\w.<>,?[\]]+\s+)+([A-Za-z_][A-Za-z0-9_]*)\s*\(/.exec(line);
  if (typed?.[1] && !SKIP_CALLS.has(typed[1])) return typed[1];
  const plain = /\bvoid\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/.exec(line);
  if (plain?.[1] && !SKIP_CALLS.has(plain[1])) return plain[1];
  return undefined;
}

function calls(body: string, name: string): boolean {
  const withoutDefinition = body.replace(new RegExp(`\\b(?:fun|void|function)\\s+${name}\\s*\\(`, "g"), "");
  return new RegExp(`\\b${name}\\s*\\(`).test(withoutDefinition);
}

function usesClass(body: string, name: string): boolean {
  return new RegExp(`\\bnew\\s+${name}\\b|\\b${name}\\s*\\(`).test(body);
}
