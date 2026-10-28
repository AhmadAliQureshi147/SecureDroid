import type { Finding, ReviewDecision, SourceFile } from "./types.ts";
import { hazardReasons } from "./guard.ts";
import { ruleStillMatches } from "./rules.ts";

export function unifiedDiff(file: string, before: string, after: string): string {
  const oldLines = before.split("\n");
  const newLines = after.split("\n");
  let start = 0;
  while (start < oldLines.length && start < newLines.length && oldLines[start] === newLines[start]) start += 1;
  let endOld = oldLines.length - 1;
  let endNew = newLines.length - 1;
  while (endOld >= start && endNew >= start && oldLines[endOld] === newLines[endNew]) {
    endOld -= 1;
    endNew -= 1;
  }
  const context = 3;
  const from = Math.max(0, start - context);
  const oldSlice = oldLines.slice(from, Math.min(oldLines.length, endOld + context + 1));
  const newSlice = newLines.slice(from, Math.min(newLines.length, endNew + context + 1));
  const body = [
    ...oldSlice.map((line) => `-${line}`),
    ...newSlice.map((line) => `+${line}`),
  ];
  return [`--- a/${file}`, `+++ b/${file}`, `@@ -${from + 1},${oldSlice.length} +${from + 1},${newSlice.length} @@`, ...body].join("\n");
}

function patchReleaseDebuggable(text: string): string | undefined {
  const startMatch = /\brelease\s*\{/.exec(text);
  if (!startMatch || startMatch.index === undefined) return undefined;
  let depth = 0;
  let end = -1;
  for (let i = startMatch.index; i < text.length; i++) {
    if (text[i] === "{") depth += 1;
    if (text[i] === "}") {
      depth -= 1;
      if (depth === 0) {
        end = i;
        break;
      }
    }
  }
  if (end < 0) return undefined;
  const block = text.slice(startMatch.index, end + 1);
  const patched = block
    .replace(/isDebuggable\s*=\s*true/, "isDebuggable = false")
    .replace(/\bdebuggable\s*=\s*true/, "debuggable = false")
    .replace(/\bdebuggable\s+true/, "debuggable false");
  if (patched === block) return undefined;
  return text.slice(0, startMatch.index) + patched + text.slice(end + 1);
}

function replaceLine(text: string, lineNumber: number, transform: (line: string) => string | undefined): string | undefined {
  const lines = text.split("\n");
  const current = lines[lineNumber - 1];
  if (current === undefined) return undefined;
  const next = transform(current);
  if (next === undefined || next === current) return undefined;
  lines[lineNumber - 1] = next;
  return lines.join("\n");
}

export function proposePatch(finding: Finding, before: string): { after?: string; kind: "patch" | "recommendation"; note: string } {
  if (finding.ruleId === "STORAGE-WORLD-ACCESSIBLE") {
    const after = before.replace(/MODE_WORLD_READABLE/g, "MODE_PRIVATE").replace(/MODE_WORLD_WRITEABLE/g, "MODE_PRIVATE");
    if (after !== before) return { after, kind: "patch", note: "Replace the world-accessible mode with MODE_PRIVATE." };
  }
  if (finding.ruleId === "BUILD-RELEASE-DEBUGGABLE") {
    const after = patchReleaseDebuggable(before);
    if (after) return { after, kind: "patch", note: "Turn debuggable off for the release build type." };
  }
  if (finding.ruleId === "ANDROID-EXPORTED-COMPONENT") {
    const after = replaceLine(before, finding.line, (line) =>
      line.includes('android:exported="true"') ? line.replace('android:exported="true"', 'android:exported="false"') : undefined,
    );
    if (after) {
      return {
        after,
        kind: "patch",
        note: "This sets exported to false. Accept it only if no other application is supposed to start this component.",
      };
    }
  }
  if (finding.ruleId === "NETWORK-CLEARTEXT") {
    const after = replaceLine(before, finding.line, (line) => {
      if (line.includes('android:usesCleartextTraffic="true"')) {
        return line.replace('android:usesCleartextTraffic="true"', 'android:usesCleartextTraffic="false"');
      }
      if (line.includes('cleartextTrafficPermitted="true"')) {
        return line.replace('cleartextTrafficPermitted="true"', 'cleartextTrafficPermitted="false"');
      }
      return undefined;
    });
    if (after) {
      return {
        after,
        kind: "patch",
        note: "This turns cleartext off on this line. Confirm every production endpoint already uses https.",
      };
    }
  }
  if (finding.ruleId === "WEBVIEW-DEBUG") {
    const after = replaceLine(before, finding.line, (line) =>
      /setWebContentsDebuggingEnabled\s*\(\s*true\s*\)/.test(line)
        ? line.replace(/setWebContentsDebuggingEnabled\s*\(\s*true\s*\)/, "setWebContentsDebuggingEnabled(false)")
        : undefined,
    );
    if (after) return { after, kind: "patch", note: "This turns WebView debugging off. Keep a debug-only call if you still need it while developing." };
  }
  if (finding.ruleId === "NETWORK-MIXED-CONTENT") {
    const after = replaceLine(before, finding.line, (line) =>
      line.includes("MIXED_CONTENT_ALWAYS_ALLOW") ? line.replace("MIXED_CONTENT_ALWAYS_ALLOW", "MIXED_CONTENT_NEVER_ALLOW") : undefined,
    );
    if (after) return { after, kind: "patch", note: "This stops the WebView from allowing mixed content." };
  }
  if (finding.ruleId === "ANDROID-DEBUGGABLE") {
    const after = before.replace('android:debuggable="true"', 'android:debuggable="false"');
    if (after !== before) return { after, kind: "patch", note: "This turns the manifest debug flag off. Confirm the debug build type still enables it." };
  }
  return {
    kind: "recommendation",
    note: finding.recommendation,
  };
}

export function reviewChange(finding: Finding, before: string, after: string | undefined, files: SourceFile[]): ReviewDecision {
  if (after === undefined) {
    return {
      decision: "recommendation-only",
      reasons: ["No safe automatic transformation is available.", finding.recommendation],
    };
  }
  const reasons = hazardReasons(before, after);
  const patchedFile: SourceFile = { path: finding.path, text: after };
  const stillMatches = ruleStillMatches(finding.ruleId, patchedFile, files.map((file) => (file.path === finding.path ? patchedFile : file)));
  if (/@(SuppressLint|Suppress)\b/.test(after) && !/@(SuppressLint|Suppress)\b/.test(before)) {
    reasons.push("The patch adds a suppression annotation.");
  }
  if (stillMatches) reasons.push("The original check still matches the patched file.");
  if (reasons.length > 0) return { decision: "blocked", reasons };
  if (finding.recipe === "automatic") return { decision: "ready", reasons: ["The staged change clears the original check."] };
  return {
    decision: "needs-review",
    reasons: ["The check no longer matches, and the behavior change still needs a developer decision."],
  };
}
