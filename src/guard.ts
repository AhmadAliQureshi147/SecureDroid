const HAZARDS: Array<{ id: string; pattern: RegExp; reason: string; severe: boolean }> = [
  {
    id: "trust-all",
    pattern: /(?:void|fun)\s+checkServerTrusted\s*\([^)]*\)\s*\{\s*\}/,
    reason: "This change adds a TrustManager that accepts every certificate.",
    severe: true,
  },
  {
    id: "hostname",
    pattern: /boolean\s+verify\s*\([^)]*\)\s*\{\s*return\s+true\s*;\s*\}|HostnameVerifier\s*\{\s*_\s*,\s*_\s*->\s*true\s*\}/,
    reason: "This change adds a hostname verifier that always returns true.",
    severe: true,
  },
  {
    id: "ssl-proceed",
    pattern: /onReceivedSslError[\s\S]{0,400}?handler\.proceed\s*\(/,
    reason: "This change continues a WebView load after a TLS error.",
    severe: true,
  },
  {
    id: "world",
    pattern: /MODE_WORLD_(?:READ|WRITE)ABLE/,
    reason: "This change uses a world-accessible file mode.",
    severe: true,
  },
  {
    id: "universal-file",
    pattern: /setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)/,
    reason: "This change enables universal file access in a WebView.",
    severe: true,
  },
  {
    id: "debuggable",
    pattern: /android:debuggable\s*=\s*"true"|isDebuggable\s*=\s*true/,
    reason: "This change turns debuggable on.",
    severe: false,
  },
  {
    id: "cleartext",
    pattern: /usesCleartextTraffic\s*=\s*"true"|cleartextTrafficPermitted\s*=\s*"true"/,
    reason: "This change permits cleartext traffic.",
    severe: false,
  },
];

export function hazardReasons(before: string, after: string): string[] {
  const reasons: string[] = [];
  for (const hazard of HAZARDS) {
    if (hazard.pattern.test(after) && !hazard.pattern.test(before)) reasons.push(hazard.reason);
  }
  if (/checkCallingPermission|enforceCallingPermission|getCallingUid/.test(before)) {
    if (!/checkCallingPermission|enforceCallingPermission|getCallingUid/.test(after)) {
      reasons.push("This change removes an authorization check that was present.");
    }
  }
  return reasons;
}

export function guardToolCall(toolName: string, input: Record<string, unknown>): { block: boolean; reason?: string } {
  if (toolName !== "write" && toolName !== "edit" && toolName !== "ast_edit") return { block: false };
  const after = changedText(input);
  const before = previousText(input);
  if (!after) return { block: false };
  for (const hazard of HAZARDS) {
    const present = hazard.pattern.test(after);
    if (!present) continue;
    const introduced = before === undefined ? hazard.severe : present && !hazard.pattern.test(before);
    if (introduced) return { block: true, reason: hazard.reason };
  }
  return { block: false };
}

function changedText(input: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(input)) {
    if (!/content|new|replacement|text|patch/i.test(key)) continue;
    if (/old|previous|original/i.test(key)) continue;
    if (typeof value === "string") parts.push(value);
  }
  return parts.join("\n");
}

function previousText(input: Record<string, unknown>): string | undefined {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(input)) {
    if (!/old|previous|original/i.test(key)) continue;
    if (typeof value === "string") parts.push(value);
  }
  return parts.length > 0 ? parts.join("\n") : undefined;
}
