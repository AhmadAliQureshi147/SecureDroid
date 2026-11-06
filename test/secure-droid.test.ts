import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { evaluate, evaluateRepository } from "../src/analysis.ts";
import { brainStatus } from "../src/brain.ts";
import { runSecureDroid } from "../src/engine.ts";
import { guardToolCall } from "../src/guard.ts";
import secureDroid from "../src/index.ts";
import { findingsFromAstGrep, findingsFromSemgrep } from "../src/engines.ts";
import { signatureHits } from "../src/signatures.ts";
import { summarizeGraphPath } from "../src/graphify.ts";
import { linksForDirectory } from "../src/source.ts";
import { checkFileSyntax } from "../src/syntax.ts";
import { proposePatch, reviewChange } from "../src/patch.ts";
import { MASVS_REQUIREMENTS, STANDARDS, UNMAPPED_REQUIREMENTS } from "../src/standards.ts";
import { resolveInside } from "../src/text.ts";
import type { Finding } from "../src/types.ts";

const fixtures = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "fixtures");

function ids(findings: Finding[]): string {
  return findings.map((finding) => `${finding.ruleId} ${finding.severity} ${finding.confidence} ${finding.subject ?? ""} ${finding.path}`).join("\n");
}

function project(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "securedroid-"));
}

function stubFinding(ruleId: string): Finding {
  return {
    id: ruleId,
    title: ruleId,
    language: "kotlin",
    path: "app/src/main/java/example/File.kt",
    line: 1,
    severity: "P2",
    confidence: "high",
    category: "platform",
    ruleId,
    detectionMethods: ["pattern"],
    evidence: [],
    attackScenario: "",
    preconditions: [],
    why: "",
    recommendation: "fix it safely",
    recipe: "automatic",
    runtime: { exposure: "build-time", summary: "" },
    verification: { status: "not-run", checks: [] },
    status: "open",
    fingerprint: "x",
    masvs: [],
    updatedAt: "",
  };
}

function write(root: string, relative: string, text: string): void {
  const full = path.join(root, relative);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, text);
}

test("detects native, compose, flutter, and react native projects", () => {
  const native = evaluateRepository(path.join(fixtures, "native-android"));
  assert.equal(native.detection.isAndroid, true);
  assert.ok(native.detection.frameworks.includes("native-android"));
  assert.ok(native.detection.languages.includes("kotlin"));
  assert.ok(native.detection.languages.includes("java"));
  for (const language of ["cpp", "csharp", "python", "rust", "ruby", "lua", "html", "css", "groovy"]) {
    assert.ok(native.detection.languages.includes(language), language);
  }
  const brain = brainStatus();
  assert.match(brain, /grok-4\.7/);
  assert.doesNotMatch(brain, /crsr_/);

  const compose = evaluateRepository(path.join(fixtures, "compose"));
  assert.ok(compose.detection.frameworks.includes("compose"));

  const flutter = evaluateRepository(path.join(fixtures, "flutter"));
  assert.ok(flutter.detection.frameworks.includes("flutter"));
  assert.ok(flutter.detection.frameworks.includes("native-android"));
  assert.ok(flutter.detection.languages.includes("dart"));

  const reactNative = evaluateRepository(path.join(fixtures, "react-native"));
  assert.ok(reactNative.detection.frameworks.includes("react-native"));
  assert.ok(reactNative.detection.languages.includes("typescript"));
});

test("native fixture finds planted issues and skips mitigated or safe code", () => {
  const { findings } = evaluateRepository(path.join(fixtures, "native-android"));
  const rules = new Set(findings.map((finding) => finding.ruleId));
  for (const rule of [
    "ANDROID-EXPORTED-COMPONENT",
    "ANDROID-DEBUGGABLE",
    "ANDROID-BACKUP",
    "NETWORK-CLEARTEXT",
    "NETWORK-TRUST-ALL",
    "NETWORK-HOSTNAME-VERIFIER",
    "NETWORK-USER-CA",
    "WEBVIEW-JS-BRIDGE",
    "WEBVIEW-UNTRUSTED-URL",
    "SECRET-HARDCODED",
    "SECRET-PRIVATE-KEY",
    "CRYPTO-ECB",
    "CRYPTO-STATIC-IV",
    "CRYPTO-WEAK-PASSWORD-HASH",
    "STORAGE-WORLD-ACCESSIBLE",
    "PRIVACY-LOG",
    "INJECTION-SQL",
    "PLATFORM-INTENT-REDIRECT",
    "PLATFORM-MUTABLE-PENDING-INTENT",
    "BUILD-RELEASE-DEBUGGABLE",
    "BUILD-SIGNING-SECRET",
    "NETWORK-SSL-ERROR-PROCEED",
    "NETWORK-MIXED-CONTENT",
    "CRYPTO-WEAK-ALGORITHM",
    "CRYPTO-HARDCODED-KEY",
    "CRYPTO-INSECURE-RANDOM",
    "STORAGE-EXTERNAL",
    "STORAGE-LEGACY-EXTERNAL",
    "PRIVACY-CLIPBOARD",
    "WEBVIEW-DEBUG",
    "WEBVIEW-JS-URL",
    "WEBVIEW-FILE-ACCESS",
    "INJECTION-ZIP-SLIP",
    "INJECTION-PATH",
    "CODE-DESERIALIZATION",
    "PLATFORM-NORMAL-PERMISSION",
    "ANDROID-IMPLICIT-EXPORT",
    "NETWORK-WEAK-TLS",
    "PLATFORM-PARSE-URI",
    "CODE-DYNAMIC-LOAD",
    "WEBVIEW-SAFE-BROWSING",
    "STORAGE-PROVIDER-PATH",
    "PLATFORM-SHARED-USER-ID",
  ]) {
    assert.ok(rules.has(rule), `missing ${rule}\n${ids(findings)}`);
  }

  const deepLink = findings.find((finding) => finding.subject === ".DeepLinkActivity");
  assert.equal(deepLink?.severity, "P1");
  assert.equal(deepLink?.confidence, "high");
  assert.equal(deepLink?.runtime.exposure, "runtime-reachable");
  assert.ok(deepLink?.detectionMethods.includes("cross-file"));

  const bridge = findings.find((finding) => finding.subject === ".AuthBridgeActivity");
  assert.equal(bridge?.confidence, "medium");
  assert.equal(bridge?.severity, "P2");
  assert.equal(bridge?.runtime.exposure, "runtime-conditional");
  const signing = findings.find((finding) => finding.ruleId === "BUILD-SIGNING-SECRET");
  assert.equal(signing?.runtime.exposure, "build-time");
  const cleartext = findings.find((finding) => finding.ruleId === "NETWORK-CLEARTEXT");
  assert.equal(cleartext?.runtime.exposure, "build-time");
  const trust = findings.find((finding) => finding.ruleId === "NETWORK-TRUST-ALL");
  assert.equal(trust?.runtime.exposure, "runtime-conditional");
  assert.equal(findings.find((finding) => finding.ruleId === "NETWORK-WEAK-TLS")?.runtime.exposure, "runtime-reachable");
  const world = findings.find((finding) => finding.ruleId === "STORAGE-WORLD-ACCESSIBLE");
  assert.equal(world?.runtime.exposure, "runtime-conditional");

  const provider = findings.find((finding) => finding.subject === ".LeakProvider");
  assert.equal(provider?.confidence, "high");

  assert.equal(findings.some((finding) => finding.subject === ".MainActivity"), false);
  assert.equal(findings.some((finding) => finding.subject === ".ProtectedActivity"), false);
  assert.equal(findings.some((finding) => finding.path.endsWith("SafeWebView.kt")), false);

  const serialized = JSON.stringify(findings);
  assert.equal(serialized.includes("super-secret-value"), false);
  assert.equal(serialized.includes("FAKEKEYMATERIAL"), false);
  assert.equal(serialized.includes("0123456789abcdef"), false);
  assert.equal(findings.some((finding) => finding.title.includes("INTERNAL")), false);
  assert.ok(findings.some((finding) => finding.subject === ".ImplicitShare"));
});

test("compose, flutter, react native, and clean fixtures stay in their lanes", () => {
  const compose = evaluateRepository(path.join(fixtures, "compose")).findings;
  assert.ok(compose.some((finding) => finding.ruleId === "PRIVACY-LOG" && finding.path.endsWith("Balance.kt")));
  assert.equal(compose.some((finding) => finding.path.endsWith("SafeScreen.kt")), false);

  const flutter = evaluateRepository(path.join(fixtures, "flutter")).findings;
  assert.ok(flutter.some((finding) => finding.ruleId === "FLUTTER-BAD-CERTIFICATE"));
  assert.ok(flutter.some((finding) => finding.ruleId === "STORAGE-PREFS-SECRET"));
  assert.ok(flutter.some((finding) => finding.ruleId === "INJECTION-COMMAND"));
  assert.ok(flutter.some((finding) => finding.subject === ".ChannelBridge"));

  const reactNative = evaluateRepository(path.join(fixtures, "react-native")).findings;
  assert.ok(reactNative.some((finding) => finding.ruleId === "STORAGE-ASYNC-SECRET"));
  assert.ok(reactNative.some((finding) => finding.ruleId === "WEBVIEW-ORIGIN-WILDCARD"));
  assert.ok(reactNative.some((finding) => finding.ruleId === "INJECTION-COMMAND"));

  const clean = evaluateRepository(path.join(fixtures, "clean")).findings.filter((finding) =>
    ["P0", "P1", "P2"].includes(finding.severity),
  );
  assert.deepEqual(clean, []);
});

test("every MASVS requirement is either implemented or explicitly out of pattern scope", () => {
  const seen = new Set<string>();
  for (const name of ["native-android", "compose", "flutter", "react-native", "clean"]) {
    for (const finding of evaluateRepository(path.join(fixtures, name)).findings) seen.add(finding.ruleId);
  }
  assert.deepEqual([...seen].sort(), Object.keys(STANDARDS).filter((id) => id !== "LLM-INVESTIGATION").sort());
  const covered = new Set(Object.values(STANDARDS).flatMap((standard) => standard.masvs));
  const explained = new Set(UNMAPPED_REQUIREMENTS.map((item) => item.id));
  for (const id of MASVS_REQUIREMENTS) {
    assert.equal(covered.has(id) || explained.has(id), true, id);
    assert.equal(covered.has(id) && explained.has(id), false, id);
  }
});

test("debug-guarded WebView debugging and checked zip paths are not findings", () => {
  const guarded = evaluate([
    {
      path: "app/src/main/java/example/DebugWeb.kt",
      text: "fun enable() {\n  if (BuildConfig.DEBUG) WebView.setWebContentsDebuggingEnabled(true)\n}\n",
    },
    {
      path: "app/src/main/java/example/SafeZip.kt",
      text: "fun unzip(entry: ZipEntry, dest: File): File {\n  val out = File(dest, entry.name)\n  if (!out.canonicalPath.startsWith(dest.canonicalPath)) error(\"zip slip\")\n  return out\n}\n",
    },
  ]);
  assert.equal(guarded.findings.some((finding) => finding.ruleId === "WEBVIEW-DEBUG"), false);
  assert.equal(guarded.findings.some((finding) => finding.ruleId === "INJECTION-ZIP-SLIP"), false);
});

test("added Android rules catch the insecure call and leave the safe call", () => {
  const hit = evaluate([
    {
      path: "app/src/main/java/example/More.kt",
      text: [
        "fun risky(intent: android.content.Intent) {",
        "  javax.crypto.Cipher.getInstance(\"AES\")",
        "  createPackageContext(\"com.other.app\", CONTEXT_INCLUDE_CODE)",
        "  System.load(intent.getStringExtra(\"native\"))",
        "  java.security.SecureRandom().setSeed(7)",
        "  okhttp3.logging.HttpLoggingInterceptor().setLevel(okhttp3.logging.HttpLoggingInterceptor.Level.BODY)",
        "  ssl.setEnabledProtocols(arrayOf(\"TLSv1\"))",
        "}",
      ].join("\n"),
    },
    {
      path: "app/src/main/AndroidManifest.xml",
      text: `<manifest><application><activity android:name=".Other" android:exported="false" android:allowTaskReparenting="true" /></application></manifest>`,
    },
  ]);
  for (const ruleId of ["CRYPTO-ECB", "CODE-PACKAGE-CONTEXT", "CODE-NATIVE-LOAD", "CRYPTO-STATIC-SEED", "PRIVACY-HTTP-BODY", "NETWORK-WEAK-TLS", "PLATFORM-TASK-REPARENT"]) {
    assert.equal(hit.findings.some((finding) => finding.ruleId === ruleId), true, ruleId);
  }
  const safe = evaluate([
    {
      path: "app/src/main/java/example/SafeMore.kt",
      text: [
        "fun fine() {",
        "  javax.crypto.Cipher.getInstance(\"AES/GCM/NoPadding\")",
        "  System.loadLibrary(\"sqlcipher\")",
        "  java.util.Random().setSeed(1)",
        "  if (BuildConfig.DEBUG) logger.setLevel(okhttp3.logging.HttpLoggingInterceptor.Level.BODY)",
        "  ssl.setEnabledProtocols(arrayOf(\"TLSv1.2\", \"TLSv1.3\"))",
        "}",
      ].join("\n"),
    },
  ]);
  for (const ruleId of ["CRYPTO-ECB", "CODE-NATIVE-LOAD", "CRYPTO-STATIC-SEED", "PRIVACY-HTTP-BODY", "NETWORK-WEAK-TLS"]) {
    assert.equal(safe.findings.some((finding) => finding.ruleId === ruleId), false, ruleId);
  }
  const polyglot = evaluate([
    { path: "app/src/main/cpp/unsafe.cpp", text: "void copy(char *d, const char *s) {\n  strcpy(d, s);\n  system(s);\n}\n" },
    { path: "app/src/main/csharp/Trust.cs", text: "handler.ServerCertificateCustomValidationCallback = (a, b, c, d) => true;\n" },
    { path: "app/src/main/python/net.py", text: "requests.get(url, verify=False)\npickle.loads(blob)\n" },
    { path: "app/src/main/rust/tls.rs", text: "builder.danger_accept_invalid_certs(true)\n" },
    { path: "app/src/main/ruby/tls.rb", text: "OpenSSL::SSL::VERIFY_NONE\n" },
    { path: "app/src/main/lua/game.lua", text: "os.execute(cmd)\n" },
  ]);
  for (const ruleId of ["CODE-NATIVE-UNSAFE", "CODE-NATIVE-EXEC", "NETWORK-DOTNET-TRUST-ALL", "NETWORK-PYTHON-UNVERIFIED", "CODE-PYTHON-PICKLE", "NETWORK-RUST-INVALID-CERTS", "NETWORK-RUBY-VERIFY-NONE", "CODE-LUA-DYNAMIC"]) {
    assert.equal(polyglot.findings.some((finding) => finding.ruleId === ruleId), true, ruleId);
  }
  const held = evaluate([
    { path: "app/src/main/cpp/safe.cpp", text: "void copy(char *d, const char *s, size_t n) {\n  snprintf(d, n, \"%s\", s);\n}\n" },
    { path: "app/src/main/python/safe.py", text: "requests.get(url, verify=True)\n" },
    { path: "app/src/main/rust/safe.rs", text: "builder.danger_accept_invalid_certs(false)\n" },
  ]);
  assert.equal(held.findings.some((finding) => finding.ruleId.startsWith("CODE-NATIVE") || finding.ruleId.startsWith("NETWORK-PYTHON") || finding.ruleId.startsWith("NETWORK-RUST")), false);
});

test("javascript enabled and a protected broadcast are not confirmed vulnerabilities", () => {
  const safe = evaluate([
    {
      path: "app/src/main/java/example/Page.kt",
      text: 'fun load(webView: WebView) {\n  webView.settings.javaScriptEnabled = true\n  webView.loadUrl("https://example.com")\n}\n',
    },
  ]);
  assert.deepEqual(safe.findings, []);

  const boot = evaluate([
    {
      path: "app/src/main/AndroidManifest.xml",
      text: `<manifest><application><receiver android:name=".Boot" android:exported="true"><intent-filter><action android:name="android.intent.action.BOOT_COMPLETED" /></intent-filter></receiver></application></manifest>`,
    },
  ]);
  assert.equal(boot.findings[0]?.severity, "informational");
  assert.equal(boot.findings[0]?.confidence, "low");

  const literal = evaluate([
    { path: "app/src/main/java/example/Tool.java", text: 'class Tool { void run() { Runtime.getRuntime().exec("echo ok"); } }\n' },
  ]);
  assert.equal(literal.findings.some((finding) => finding.ruleId === "INJECTION-COMMAND"), false);
});

test("finding ids are stable and paths cannot escape the repository", () => {
  const first = evaluateRepository(path.join(fixtures, "native-android"));
  const second = evaluateRepository(path.join(fixtures, "native-android"));
  assert.ok(first.findings.length > 0);
  assert.deepEqual(first.findings.map((finding) => finding.id), second.findings.map((finding) => finding.id));
  const root = project();
  assert.throws(() => resolveInside(root, "../outside"), /escapes/);
});

test("staged fixes can be rejected, refuse stale files, and save only after acceptance", () => {
  const root = project();
  write(
    root,
    "app/src/main/AndroidManifest.xml",
    `<manifest package="com.example.demo"><application android:allowBackup="false"><activity android:name=".MainActivity" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN" /><category android:name="android.intent.category.LAUNCHER" /></intent-filter></activity></application></manifest>`,
  );
  write(
    root,
    "app/build.gradle.kts",
    "android {\n  buildTypes {\n    debug { isDebuggable = true }\n    release { isDebuggable = true }\n  }\n}\n",
  );
  const storage = "fun save() {\n  openFileOutput(\"notes\", MODE_WORLD_READABLE)\n}\n";
  write(root, "app/src/main/java/example/Storage.kt", storage);

  const scan = runSecureDroid({ action: "scan", root });
  const findings = scan.data as Finding[];
  const world = findings.find((finding) => finding.ruleId === "STORAGE-WORLD-ACCESSIBLE");
  const release = findings.find((finding) => finding.ruleId === "BUILD-RELEASE-DEBUGGABLE");
  assert.ok(world);
  assert.ok(release);

  const staged = runSecureDroid({ action: "fix", root, findingId: world.id });
  assert.match(staged.text, /partial/);
  assert.doesNotMatch(staged.text, /Verification: passed/);
  assert.equal(fs.readFileSync(path.join(root, "app/src/main/java/example/Storage.kt"), "utf8"), storage);

  const rejected = runSecureDroid({ action: "reject", root, findingId: world.id });
  assert.match(rejected.text, /unchanged/);
  assert.equal(fs.readFileSync(path.join(root, "app/src/main/java/example/Storage.kt"), "utf8"), storage);

  runSecureDroid({ action: "fix", root, findingId: world.id });
  fs.appendFileSync(path.join(root, "app/src/main/java/example/Storage.kt"), "\n// touched\n");
  const stale = runSecureDroid({ action: "accept", root, findingId: world.id });
  assert.equal(stale.ok, false);
  assert.match(fs.readFileSync(path.join(root, "app/src/main/java/example/Storage.kt"), "utf8"), /MODE_WORLD_READABLE/);
  assert.match(fs.readFileSync(path.join(root, "app/src/main/java/example/Storage.kt"), "utf8"), /touched/);

  write(root, "app/src/main/java/example/Storage.kt", storage);
  runSecureDroid({ action: "scan", root });
  const rescanned = (runSecureDroid({ action: "status", root }).data as { findings: Finding[] }).findings;
  const fresh = rescanned.find((finding) => finding.ruleId === "STORAGE-WORLD-ACCESSIBLE" && finding.status !== "fixed");
  assert.ok(fresh);
  runSecureDroid({ action: "fix", root, findingId: fresh.id });
  const accepted = runSecureDroid({ action: "accept", root, findingId: fresh.id });
  assert.equal(accepted.ok, true, accepted.text);
  const saved = fs.readFileSync(path.join(root, "app/src/main/java/example/Storage.kt"), "utf8");
  assert.match(saved, /MODE_PRIVATE/);
  assert.doesNotMatch(saved, /MODE_WORLD_READABLE/);
  assert.equal((accepted.data as Finding).status, "fixed");

  const releaseStage = runSecureDroid({ action: "fix", root, findingId: release.id });
  assert.equal(releaseStage.ok, true, releaseStage.text);
  const releaseSaved = runSecureDroid({ action: "accept", root, findingId: release.id });
  assert.equal(releaseSaved.ok, true, releaseSaved.text);
  const gradle = fs.readFileSync(path.join(root, "app/build.gradle.kts"), "utf8");
  assert.match(gradle, /debug \{ isDebuggable = true \}/);
  assert.match(gradle, /release \{ isDebuggable = false \}/);
});

test("review blocks weakened security and suppression, and exceptions expire when evidence changes", () => {
  const before = "fun save() {\n  if (checkCallingPermission(\"p\") != 0) return\n  openFileOutput(\"notes\", MODE_WORLD_READABLE)\n}\n";
  const finding = {
    id: "demo",
    title: "demo",
    language: "kotlin" as const,
    path: "app/src/main/java/example/Storage.kt",
    line: 3,
    severity: "P1" as const,
    confidence: "confirmed" as const,
    category: "storage" as const,
    ruleId: "STORAGE-WORLD-ACCESSIBLE",
    detectionMethods: ["pattern" as const],
    evidence: [],
    attackScenario: "",
    preconditions: [],
    why: "",
    recommendation: "",
    recipe: "automatic" as const,
    verification: { status: "not-run" as const, checks: [] },
    status: "open" as const,
    fingerprint: "abc",
    masvs: [],
    updatedAt: "",
  };
  const suppressed = reviewChange(
    finding,
    before,
    before.replace("MODE_WORLD_READABLE", "MODE_WORLD_READABLE /* @SuppressLint(\"World\") */"),
    [{ path: finding.path, text: before }],
  );
  assert.equal(suppressed.decision, "blocked");

  const weakened = reviewChange(
    finding,
    before,
    before.replace("checkCallingPermission", "removedCheck"),
    [{ path: finding.path, text: before }],
  );
  assert.equal(weakened.decision, "blocked");
  assert.match(weakened.reasons.join(" "), /authorization/);

  const root = project();
  write(root, "app/src/main/java/example/Secrets.kt", 'const val apiKey = "super-secret-value"\n');
  write(root, "app/src/main/AndroidManifest.xml", `<manifest package="com.example.demo"><application android:allowBackup="false" /></manifest>`);
  const scan = runSecureDroid({ action: "scan", root });
  const secret = (scan.data as Finding[]).find((item) => item.ruleId === "SECRET-HARDCODED");
  assert.ok(secret);
  const recorded = runSecureDroid({
    action: "except",
    root,
    findingId: secret.id,
    reason: "Test fixture credential accepted for this build.",
  });
  assert.equal(recorded.ok, true, recorded.text);
  const again = runSecureDroid({ action: "scan", root });
  const suppressedFinding = (again.data as Finding[]).find((item) => item.id === secret.id);
  assert.equal(suppressedFinding?.status, "suppressed");

  write(root, "app/src/main/java/example/Secrets.kt", 'const val apiKey = "rotated-secret-value"\n');
  const rotated = runSecureDroid({ action: "scan", root });
  const open = (rotated.data as Finding[]).filter((item) => item.ruleId === "SECRET-HARDCODED" && item.status === "open");
  assert.equal(open.length, 1);
  assert.notEqual(open[0]?.id, secret.id);
});

test("the model tool cannot accept patches, and unsafe writes are blocked", async () => {
  let actions: readonly string[] = [];
  const commands: string[] = [];
  const handlers = new Map<string, (event: { systemPrompt?: string[]; reason?: string }, ctx: { cwd?: string }) => unknown>();
  let pending: Promise<{ content: Array<{ text: string }> }> | undefined;
  const fake = {
    zod: {
      object: (shape: Record<string, unknown>) => shape,
      string: () => ({ describe() { return this; }, optional() { return this; } }),
      enum: (values: readonly string[]) => {
        actions = values;
        return values;
      },
    },
    setLabel() {},
    on(event: string, handler: (event: never, ctx: never) => unknown) {
      handlers.set(event, handler as (event: { systemPrompt?: string[]; reason?: string }, ctx: { cwd?: string }) => unknown);
    },
    registerTool(tool: { execute: (id: string, params: Record<string, unknown>, signal: AbortSignal, update: unknown, ctx: { cwd?: string }) => Promise<{ content: Array<{ text: string }> }> }) {
      pending = tool.execute("1", { action: "detect" }, new AbortController().signal, undefined, { cwd: project() });
    },
    registerCommand(name: string) {
      commands.push(name);
    },
    sendMessage() {},
    sendUserMessage() {},
  };
  secureDroid(fake as never);
  assert.equal(actions.includes("accept"), false);
  assert.equal(actions.includes("record"), true);
  assert.equal(actions.includes("judge"), true);
  assert.equal(actions.includes("remediate"), true);
  assert.equal(actions.includes("read"), true);
  assert.equal(actions.includes("scan"), true);
  assert.equal(actions.includes("review"), false);
  assert.equal(actions.includes("audit"), false);
  assert.ok(commands.includes("android-triage"));
  assert.ok(commands.includes("android-accept"));
  assert.ok(commands.includes("android-remediate"));
  const executed = await pending;
  assert.match(executed?.content[0]?.text ?? "", /Android project/);

  const blocked = guardToolCall("write", { content: "void checkServerTrusted(X509Certificate[] c, String a) {}" });
  assert.equal(blocked.block, true);
  const allowed = guardToolCall("edit", {
    old_string: "void checkServerTrusted(X509Certificate[] c, String a) {}",
    new_string: "void checkServerTrusted(X509Certificate[] c, String a) { check(c); }",
  });
  assert.equal(allowed.block, false);

  const empty = project();
  const idle = handlers.get("before_agent_start")?.({ systemPrompt: ["base"], reason: "prompt" }, { cwd: empty });
  assert.equal(idle, undefined);
  const android = project();
  write(android, "app/src/main/AndroidManifest.xml", "<manifest></manifest>");
  const policy = handlers.get("before_agent_start")?.({ systemPrompt: ["base"], reason: "prompt" }, { cwd: android }) as { systemPrompt: string[] };
  assert.equal(policy.systemPrompt[0], "base");
  assert.match(policy.systemPrompt[1] ?? "", /SecureDroid/);
  assert.equal(handlers.get("before_agent_start")?.({ systemPrompt: ["base"], reason: "revive" }, { cwd: android }), undefined);
});

test("the Oh My Pi checkout is wired in as the agent runtime", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(fixtures, "..", "oh-my-pi", "package.json"), "utf8")) as { name: string };
  assert.equal(pkg.name, "omp");
  const types = fs.readFileSync(
    path.join(fixtures, "..", "oh-my-pi", "packages", "coding-agent", "src", "extensibility", "extensions", "types.ts"),
    "utf8",
  );
  assert.match(types, /registerTool/);
  assert.match(types, /before_agent_start/);
  assert.match(types, /zod: typeof zod/);
  const script = fs.readFileSync(path.join(fixtures, "..", "scripts", "omp.sh"), "utf8");
  assert.match(script, /--extension/);
  assert.match(script, /--append-system-prompt/);
  assert.match(script, /oh-my-pi\/packages\/coding-agent\/src\/cli\.ts/);
  const root = path.join(fixtures, "..");
  assert.equal(fs.existsSync(path.join(root, "prompts", "harness.md")), true);
  for (const agent of ["android-security.md", "android-runtime.md", "android-verifier.md", "android-fixer.md", "android-reviewer.md"]) {
    const text = fs.readFileSync(path.join(root, "agents", agent), "utf8");
    assert.match(text, /^---\nname:/);
  }
  const launcher = fs.readFileSync(path.join(root, "oh-my-pi", "securedroid.sh"), "utf8");
  assert.match(launcher, /scripts\/omp\.sh/);
});

test("external matches are kept only when the built-in rule still matches", () => {
  const trust = "public class TrustAll {\n  public void checkServerTrusted(X509Certificate[] c, String a) {}\n}\n";
  const guarded = "fun enable() {\n  if (BuildConfig.DEBUG) WebView.setWebContentsDebuggingEnabled(true)\n}\n";
  const files = [
    { path: "app/Trust.java", text: trust },
    { path: "app/DebugWeb.kt", text: guarded },
  ];
  const parsed = findingsFromSemgrep(
    JSON.stringify({
      results: [
        { check_id: "android.NETWORK-TRUST-ALL", path: "app/Trust.java", start: { line: 2 }, extra: { message: "empty trust" } },
        { check_id: "android.WEBVIEW-DEBUG", path: "app/DebugWeb.kt", start: { line: 2 }, extra: { message: "debug" } },
        { check_id: "not-a-rule", path: "app/Trust.java", start: { line: 1 }, extra: { message: "nope" } },
        { check_id: "android.NETWORK-TRUST-ALL", path: "/tmp/outside.kt", start: { line: 2 }, extra: { message: "absolute" } },
      ],
    }),
    "",
    files,
  );
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0]?.ruleId, "NETWORK-TRUST-ALL");
  assert.equal(parsed[0]?.confidence, "medium");
  assert.equal(parsed[0]?.runtime.exposure, "runtime-conditional");

  const ast = findingsFromAstGrep(
    JSON.stringify([
      {
        ruleId: "NETWORK-TRUST-ALL",
        file: "app/Trust.java",
        message: "empty trust",
        range: { start: { line: 1 } },
      },
    ]),
    "",
    files,
  );
  assert.equal(ast.length, 1);
  assert.equal(ast[0]?.line, 2);
});

test("runtime follows a call from an exported component and stops at an uncalled function", () => {
  const result = evaluate([
    {
      path: "app/src/main/AndroidManifest.xml",
      text: '<manifest><application><activity android:name=".Home" android:exported="true" /></application></manifest>',
    },
    {
      path: "app/src/main/java/example/Home.kt",
      text: [
        "class Home : Activity() {",
        "    override fun onCreate(savedInstanceState: Bundle?) {",
        "        leakPassword()",
        "        used(\"x\")",
        "        TrustAll()",
        "    }",
        "    private fun leakPassword() {",
        "        Log.d(\"auth\", \"password=$password\")",
        "    }",
        "    private fun unused() {",
        "        Log.d(\"auth\", \"password=$password\")",
        "    }",
        "}",
      ].join("\n"),
    },
    {
      path: "app/src/main/java/example/Calls.kt",
      text: ["fun used(password: String) {", "    Log.d(\"auth\", \"password=$password\")", "}", "fun orphan(password: String) {", "    Log.d(\"auth\", \"password=$password\")", "}"].join("\n"),
    },
    {
      path: "app/src/main/java/example/TrustAll.java",
      text: "public class TrustAll {\n    public void checkServerTrusted(X509Certificate[] c, String a) {}\n}\n",
    },
    {
      path: "app/src/main/java/example/UnusedTrust.java",
      text: "public class UnusedTrust {\n    public void checkServerTrusted(X509Certificate[] c, String a) {}\n}\n",
    },
  ]);
  const exposure = (file: string, line: number) => result.findings.find((finding) => finding.path.endsWith(file) && finding.line === line)?.runtime.exposure;
  assert.equal(exposure("Home.kt", 8), "runtime-reachable");
  assert.equal(exposure("Home.kt", 11), "runtime-conditional");
  assert.equal(exposure("Calls.kt", 2), "runtime-reachable");
  assert.equal(exposure("Calls.kt", 5), "runtime-conditional");
  assert.equal(exposure("TrustAll.java", 2), "runtime-reachable");
  assert.equal(exposure("UnusedTrust.java", 2), "runtime-conditional");
});

test("navigation, intent targets, interfaces, and compose destinations extend the call path", () => {
  const nav = evaluate([
    {
      path: "app/src/main/res/navigation/main.xml",
      text: '<navigation app:startDestination="@id/home"><fragment android:id="@+id/home" android:name="example.HomeFragment" /><fragment android:id="@+id/other" android:name="example.OtherFragment"><action app:destination="@id/detail" /></fragment><fragment android:id="@+id/detail" android:name="example.DetailFragment" /><fragment android:id="@+id/orphan" android:name="example.OrphanFragment" /></navigation>',
    },
    {
      path: "app/src/main/java/example/HomeFragment.kt",
      text: "class HomeFragment {\n  override fun onViewCreated() {\n    Log.d(\"auth\", \"password=$password\")\n  }\n}\n",
    },
    {
      path: "app/src/main/java/example/OrphanFragment.kt",
      text: "class OrphanFragment {\n  override fun onViewCreated() {\n    Log.d(\"auth\", \"password=$password\")\n  }\n}\n",
    },
  ]);
  assert.equal(nav.findings.find((finding) => finding.path.endsWith("HomeFragment.kt"))?.runtime.exposure, "runtime-reachable");
  assert.equal(nav.findings.find((finding) => finding.path.endsWith("OrphanFragment.kt"))?.runtime.exposure, "runtime-conditional");

  const intent = evaluate([
    {
      path: "app/src/main/AndroidManifest.xml",
      text: '<manifest><application><activity android:name=".Home" android:exported="true" /></application></manifest>',
    },
    {
      path: "app/src/main/java/example/Home.kt",
      text: "class Home : Activity() {\n  override fun onCreate(savedInstanceState: Bundle?) {\n    setClassName(this, \"example.Helper\")\n  }\n}\n",
    },
    {
      path: "app/src/main/java/example/Helper.kt",
      text: "class Helper {\n  fun show() {\n    Log.d(\"auth\", \"password=$password\")\n  }\n}\n",
    },
  ]);
  assert.equal(intent.findings.find((finding) => finding.path.endsWith("Helper.kt"))?.runtime.exposure, "runtime-reachable");

  const typed = evaluate([
    {
      path: "app/src/main/AndroidManifest.xml",
      text: '<manifest><application><activity android:name=".Home" android:exported="true" /></application></manifest>',
    },
    { path: "app/src/main/java/example/Screen.kt", text: "interface Screen {\n  fun render()\n}\n" },
    {
      path: "app/src/main/java/example/Detail.kt",
      text: "class Detail : Screen {\n  override fun render() {\n    Log.d(\"auth\", \"password=$password\")\n  }\n}\n",
    },
    {
      path: "app/src/main/java/example/Home.kt",
      text: "class Home : Activity() {\n  override fun onCreate(savedInstanceState: Bundle?) {\n    val screen: Screen = Detail()\n    screen.render()\n  }\n}\n",
    },
  ]);
  assert.equal(typed.findings.find((finding) => finding.path.endsWith("Detail.kt"))?.runtime.exposure, "runtime-reachable");

  const compose = evaluate([
    {
      path: "app/src/main/AndroidManifest.xml",
      text: '<manifest><application><activity android:name=".MainActivity" android:exported="true" /></application></manifest>',
    },
    {
      path: "app/src/main/java/example/MainActivity.kt",
      text: "class MainActivity : Activity() {\n  override fun onCreate(savedInstanceState: Bundle?) {\n    setContent { AppNav() }\n  }\n}\nfun AppNav() {\n  composable<DetailScreen>()\n}\n",
    },
    {
      path: "app/src/main/java/example/DetailScreen.kt",
      text: "fun DetailScreen() {\n  Log.d(\"auth\", \"password=$password\")\n}\n",
    },
  ]);
  assert.equal(compose.findings.find((finding) => finding.path.endsWith("DetailScreen.kt"))?.runtime.exposure, "runtime-reachable");
});

test("an external rule can add a comment-only trust manager the built-in pattern missed", () => {
  const commented = "fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {\n  // no certificate check\n}\n";
  const filled = "fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {\n  check(chain)\n}\n";
  const extra = findingsFromSemgrep(
    JSON.stringify({ results: [{ check_id: "NETWORK-TRUST-ALL", path: "app/Trust.kt", start: { line: 1 }, extra: { message: "empty" } }] }),
    "",
    [{ path: "app/Trust.kt", text: commented }],
  );
  assert.equal(extra.length, 1);
  const rejected = findingsFromSemgrep(
    JSON.stringify({ results: [{ check_id: "NETWORK-TRUST-ALL", path: "app/Trust.kt", start: { line: 1 }, extra: { message: "checked" } }] }),
    "",
    [{ path: "app/Trust.kt", text: filled }],
  );
  assert.equal(rejected.length, 0);
});

test("backup, manifest debug, and pending intents stage, and a broken patch fails syntax", () => {
  const backup = proposePatch(
    { ...stubFinding("ANDROID-BACKUP"), path: "app/src/main/AndroidManifest.xml", language: "xml" },
    '        android:allowBackup="true"\n',
  );
  assert.match(backup.after ?? "", /allowBackup="false"/);
  const debug = proposePatch(
    { ...stubFinding("ANDROID-DEBUGGABLE"), path: "app/src/main/AndroidManifest.xml", language: "xml" },
    '        android:debuggable="true"\n',
  );
  assert.match(debug.after ?? "", /debuggable="false"/);
  const pending = proposePatch(
    stubFinding("PLATFORM-MUTABLE-PENDING-INTENT"),
    "    return PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT)\n",
  );
  assert.match(pending.after ?? "", /FLAG_IMMUTABLE/);
  assert.equal(checkFileSyntax("fun ok() {}\n").status, "passed");
  assert.equal(checkFileSyntax("fun bad( {\n").status, "failed");
});

test("cleartext, WebView debug, and mixed content can be staged; secrets stay recommendations", () => {
  const stub = (ruleId: string, recipe: "automatic" | "manual"): Finding => ({
    id: ruleId,
    title: ruleId,
    language: "kotlin",
    path: ruleId === "NETWORK-CLEARTEXT" ? "app/src/main/res/xml/network_security_config.xml" : "app/src/main/java/example/Standards.kt",
    line: 1,
    severity: "P2",
    confidence: "high",
    category: "network",
    ruleId,
    detectionMethods: ["pattern"],
    evidence: [],
    attackScenario: "",
    preconditions: [],
    why: "",
    recommendation: "fix it safely",
    recipe,
    runtime: { exposure: "build-time", summary: "" },
    verification: { status: "not-run", checks: [] },
    status: "open",
    fingerprint: "x",
    masvs: [],
    updatedAt: "",
  });
  const clearBefore = '<base-config cleartextTrafficPermitted="true">\n';
  const clear = proposePatch(stub("NETWORK-CLEARTEXT", "automatic"), clearBefore);
  assert.equal(clear.kind, "patch");
  assert.match(clear.after ?? "", /cleartextTrafficPermitted="false"/);
  assert.equal(
    reviewChange(stub("NETWORK-CLEARTEXT", "automatic"), clearBefore, clear.after, [
      { path: "app/src/main/res/xml/network_security_config.xml", text: clear.after ?? "" },
    ]).decision,
    "ready",
  );
  const web = proposePatch(stub("WEBVIEW-DEBUG", "automatic"), "WebView.setWebContentsDebuggingEnabled(true)\n");
  assert.match(web.after ?? "", /setWebContentsDebuggingEnabled\(false\)/);
  const mixed = proposePatch(stub("NETWORK-MIXED-CONTENT", "automatic"), "settings.mixedContentMode = MIXED_CONTENT_ALWAYS_ALLOW\n");
  assert.match(mixed.after ?? "", /MIXED_CONTENT_NEVER_ALLOW/);
  assert.equal(proposePatch(stub("CRYPTO-HARDCODED-KEY", "manual"), 'SecretKeySpec("0123456789abcdef".toByteArray())\n').kind, "recommendation");
});

test("the verifier upholds a reached finding and cannot dismiss a live one", () => {
  const root = project();
  write(
    root,
    "app/src/main/AndroidManifest.xml",
    '<manifest><application android:usesCleartextTraffic="true"><activity android:name=".Home" android:exported="true" /></application></manifest>',
  );
  write(
    root,
    "app/src/main/java/example/Home.kt",
    [
      "class Home : Activity() {",
      "    override fun onCreate(savedInstanceState: Bundle?) {",
      "        leakPassword()",
      "        saveSecret(this)",
      "    }",
      "    private fun leakPassword() {",
      "        Log.d(\"auth\", \"password=$password\")",
      "    }",
      "    private fun saveSecret(context: Context) {",
      "        context.getSharedPreferences(\"a\", 0).edit().putString(\"auth_token\", \"x\").apply()",
      "    }",
      "}",
    ].join("\n"),
  );
  write(root, "app/src/main/java/example/TrustAll.java", "public class TrustAll {\n    public void checkServerTrusted(X509Certificate[] c, String a) {}\n}\n");
  const scan = runSecureDroid({ action: "scan", root });
  assert.equal(scan.ok, true, scan.text);
  assert.match(scan.text, /Verified vulnerabilities/);
  assert.match(scan.text, /ANDROID-EXPORTED-COMPONENT/);
  const findings = scan.data as Finding[];
  const cleartext = findings.find((finding) => finding.ruleId === "NETWORK-CLEARTEXT");
  const trust = findings.find((finding) => finding.ruleId === "NETWORK-TRUST-ALL");
  const leak = findings.find((finding) => finding.ruleId === "PRIVACY-LOG");
  const prefs = findings.find((finding) => finding.ruleId === "STORAGE-PREFS-SECRET");
  assert.equal(cleartext?.verdict?.result, "upheld");
  assert.equal(leak?.verdict?.result, "upheld");
  assert.equal(trust?.verdict?.result, "withheld");
  assert.equal(prefs?.verdict?.result, "withheld");
  assert.doesNotMatch(scan.text.split("Withheld")[0] ?? "", /NETWORK-TRUST-ALL/);

  const upheld = runSecureDroid({
    action: "judge",
    root,
    findingId: prefs?.id,
    decision: "uphold",
    file: "app/src/main/java/example/Home.kt",
    line: "4",
    why: "onCreate calls saveSecret, so this preference write is on the entry path.",
  });
  assert.equal(upheld.ok, true, upheld.text);
  assert.equal((upheld.data as Finding).verdict?.result, "upheld");
  assert.equal((upheld.data as Finding).confidence, "medium");

  const missed = runSecureDroid({
    action: "judge",
    root,
    findingId: trust?.id,
    decision: "uphold",
    file: "app/src/main/java/example/Home.kt",
    line: "3",
    why: "This line does not construct TrustAll.",
  });
  assert.equal(missed.ok, false);

  const dismissed = runSecureDroid({
    action: "judge",
    root,
    findingId: trust?.id,
    decision: "reject",
    file: "app/src/main/java/example/TrustAll.java",
    line: "2",
    why: "The verifier tried to hide a check that still matches.",
  });
  assert.equal(dismissed.ok, false);
  assert.match(dismissed.text, /cannot dismiss a live finding/);
});

test("the model can pin a finding to a real line, and remediate stages without writing source", () => {
  const root = project();
  const outside = runSecureDroid({
    action: "record",
    root,
    file: "../etc/passwd",
    line: "1",
    title: "Outside file",
    why: "This path leaves the repository.",
    recommendation: "Reject the path.",
    category: "storage",
    severity: "P1",
  });
  assert.equal(outside.ok, false);

  write(root, "app/src/main/java/example/App.kt", "fun hold() {\n  val token = load()\n}\n");
  const promoted = runSecureDroid({
    action: "record",
    root,
    file: "app/src/main/java/example/App.kt",
    line: "2",
    title: "Promoted issue",
    why: "The model tried to mark this confirmed and critical.",
    recommendation: "Keep the stored confidence.",
    category: "storage",
    severity: "P0",
  });
  assert.equal(promoted.ok, false);
  assert.match(promoted.text, /cannot be P0/);
  const recorded = runSecureDroid({
    action: "record",
    root,
    file: "app/src/main/java/example/App.kt",
    line: "2",
    title: "Token stays in memory",
    why: "The token is held in a local after the request that produced it.",
    recommendation: "Drop the token when the request finishes.",
    category: "storage",
    severity: "P1",
    masvs: "MASVS-STORAGE-1",
  });
  assert.equal(recorded.ok, true, recorded.text);
  const finding = recorded.data as Finding;
  assert.equal(finding.confidence, "medium");
  assert.equal(finding.severity, "P1");
  assert.equal(finding.runtime.exposure, "runtime-conditional");
  assert.deepEqual(finding.masvs, ["MASVS-STORAGE-1"]);

  const scanned = runSecureDroid({ action: "scan", root });
  assert.equal((scanned.data as Finding[]).some((item) => item.id === finding.id && item.status === "open"), true);

  write(root, "app/src/main/java/example/App.kt", "fun hold() {\n  val token = sealed()\n}\n");
  const rotated = runSecureDroid({ action: "scan", root });
  assert.equal((rotated.data as Finding[]).find((item) => item.id === finding.id)?.status, "fixed");

  const source = "fun open() {\n  openFileOutput(name, MODE_WORLD_READABLE)\n}\n";
  const app = project();
  write(app, "app/src/main/java/example/Files.kt", source);
  const staged = runSecureDroid({ action: "remediate", root: app });
  assert.equal(staged.ok, true, staged.text);
  assert.match(staged.text, /Staged 1 automatic fix/);
  assert.equal(fs.readFileSync(path.join(app, "app/src/main/java/example/Files.kt"), "utf8"), source);
  assert.match(runSecureDroid({ action: "status", root: app }).text, /staged/);
});

test("a directory read can show the code-map link beside the source", () => {
  const text = linksForDirectory(
    {
      nodes: [
        { id: "home", label: "Home", source_file: "app/Home.kt" },
        { id: "trust", label: "TrustAll", source_file: "app/Trust.kt" },
      ],
      edges: [{ source: "home", target: "trust", relation: "calls", confidence: "EXTRACTED", source_file: "app/Home.kt" }],
    },
    "app",
  );
  assert.match(text, /Home calls TrustAll \[EXTRACTED\]/);
});

test("a graph path with an inferred hop stays unconfirmed", () => {
  const inferred = summarizeGraphPath(
    "Shortest path (2 hops):\n  MainActivity --method [EXTRACTED]--> .onCreate() --calls [INFERRED 0.85]--> InsecurePractices\nPath confidence: INFERRED",
  );
  assert.equal(inferred.confidence, "inferred");
  const extracted = summarizeGraphPath("Shortest path (1 hops):\n  MainActivity --calls [EXTRACTED]--> Helper\nPath confidence: EXTRACTED");
  assert.equal(extracted.confidence, "extracted");
  const missing = summarizeGraphPath("No directed path found between 'MainActivity' and 'TrustAll'.");
  assert.equal(missing.confidence, "none");
});

test("source read shows Kotlin, Dart, and React Native code before the review finishes", () => {
  const root = project();
  write(root, "app/src/main/AndroidManifest.xml", "<manifest></manifest>\n");
  write(root, "app/src/main/java/example/Home.kt", `const val password = "super-secret-value"\nfun home() {\n${"  val markerKotlin = 1\n".repeat(500)}}\n`);
  write(root, "lib/main.dart", `void main() {\n${"  var markerDart = 1;\n".repeat(500)}}\n`);
  write(root, "App.tsx", `export function App() {\n${"  const markerReact = 1;\n".repeat(500)}}\n`);
  const first = runSecureDroid({ action: "read", root, page: "1" });
  assert.equal(first.ok, true, first.text);
  assert.match(first.text, /Source page 1 of ([2-9])/);
  const total = Number(/Source page 1 of ([2-9])/.exec(first.text)?.[1] ?? "0");
  const shown = [first.text];
  for (let page = 2; page <= total; page += 1) shown.push(runSecureDroid({ action: "read", root, page: String(page) }).text);
  const all = shown.join("\n");
  assert.match(all, /markerKotlin/);
  assert.match(all, /markerDart/);
  assert.match(all, /markerReact/);
  assert.match(all, /<redacted>/);
  assert.doesNotMatch(all, /super-secret-value/);
  assert.match(first.text, /review them for insecure Android coding/);
  assert.match(first.text, /before the next page/);
  assert.match(first.text, /continue to the next line/);
  assert.match(shown.at(-1) ?? "", /last page/);
  const done = runSecureDroid({ action: "read", root, page: "99" });
  assert.match(done.text, /past the end/);
});

test("a hypothesis stays research state and a later scan compares the baseline", () => {
  const root = project();
  write(root, "app/src/main/AndroidManifest.xml", "<manifest></manifest>\n");
  write(root, "app/src/main/java/example/Crypto.kt", 'fun x() { javax.crypto.Cipher.getInstance("AES") }\n');
  const saved = runSecureDroid({
    action: "hypothesize",
    root,
    title: "The cipher may expose repeated blocks",
    why: "The call was read. No message was encrypted in a test.",
    file: "The source line requests AES without naming a mode.",
    recommendation: "Read the callers before calling this a finding.",
    decision: "active",
  });
  assert.equal(saved.ok, true, saved.text);
  assert.match(saved.text, /not a vulnerability/);
  const index = runSecureDroid({ action: "threads", root });
  assert.match(index.text, /thr-001 active/);
  assert.doesNotMatch(index.text, /without naming a mode/);
  const one = runSecureDroid({ action: "thread", root, findingId: "thr-001" });
  assert.match(one.text, /without naming a mode/);
  const first = runSecureDroid({ action: "scan", root });
  assert.match(first.text, /Baseline saved/);
  const second = runSecureDroid({ action: "scan", root });
  assert.match(second.text, /unchanged/);
  assert.match(second.text, /Absence is not a pass/);
  const activity = runSecureDroid({ action: "activity", root });
  assert.match(activity.text, /hypothesize/);
  assert.match(activity.text, /does not prove a vulnerability/);
});

test("sigma and yara match insecure lines and skip the safe counterparts", () => {
  const hits = signatureHits([
    { path: "app/A.kt", text: "fun save() {\n  openFileOutput(\"notes\", MODE_WORLD_READABLE)\n}\n" },
    { path: "app/B.kt", text: "fun save() {\n  openFileOutput(\"notes\", MODE_PRIVATE)\n}\n" },
    { path: "app/C.kt", text: "fun enc() { Cipher.getInstance(\"AES/GCM/NoPadding\") }\n" },
    { path: "app/D.kt", text: "fun enc() { Cipher.getInstance(\"AES\") }\n" },
    { path: "app/E.kt", text: "fun stay() { PendingIntent.getActivity(this, 0, intent, FLAG_IMMUTABLE) }\n" },
    { path: "app/F.kt", text: "// MODE_WORLD_READABLE is the pattern name\n" },
  ]);
  assert.ok(hits.some((hit) => hit.engine === "sigma" && hit.ruleId === "STORAGE-WORLD-ACCESSIBLE" && hit.path.endsWith("A.kt")));
  assert.ok(hits.some((hit) => hit.engine === "yara" && hit.ruleId === "STORAGE-WORLD-ACCESSIBLE" && hit.path.endsWith("A.kt")));
  assert.ok(hits.some((hit) => hit.engine === "sigma" && hit.ruleId === "CRYPTO-ECB" && hit.path.endsWith("D.kt")));
  assert.ok(hits.some((hit) => hit.engine === "yara" && hit.ruleId === "CRYPTO-ECB" && hit.path.endsWith("D.kt")));
  assert.equal(hits.some((hit) => hit.path.endsWith("B.kt") || hit.path.endsWith("C.kt") || hit.path.endsWith("E.kt") || hit.path.endsWith("F.kt")), false);
  const ids = new Set(hits.map((hit) => hit.ruleId));
  for (const id of ids) assert.ok(STANDARDS[id], id);
});

test("a scan runs the required semgrep, sigma, and yara packs", () => {
  const root = project();
  write(root, "app/src/main/AndroidManifest.xml", "<manifest></manifest>\n");
  write(root, "app/src/main/java/example/Storage.kt", "fun save() {\n  openFileOutput(\"notes\", MODE_WORLD_READABLE)\n}\n");
  const scan = runSecureDroid({ action: "scan", root });
  assert.equal(scan.ok, true, scan.text);
  assert.match(scan.text, /External: semgrep: \d+ confirmed/);
  assert.match(scan.text, /External: sigma: \d+ confirmed/);
  assert.match(scan.text, /External: yara: \d+ confirmed/);
  assert.match(scan.text, /Source context: all \d+ directories are below/);
  assert.match(scan.text, /MODE_WORLD_READABLE/);
  assert.match(scan.text, /End of one-pass context/);
  assert.ok((scan.data as Finding[]).some((item) => item.ruleId === "STORAGE-WORLD-ACCESSIBLE"));
  assert.doesNotMatch(scan.text, /Required scanner semgrep failed|Required scanner semgrep is not installed|Required sigma pack failed|Required yara pack failed/);
  const world = (scan.data as Finding[]).find((item) => item.ruleId === "STORAGE-WORLD-ACCESSIBLE");
  assert.ok(world);
  const evidence = world.evidence.map((item) => item.description).join("\n");
  assert.match(evidence, /sigma/);
  assert.match(evidence, /yara/);
});

test("cli reports detection without claiming a clean project is vulnerable", () => {
  const result = spawnSync(process.execPath, ["--experimental-strip-types", "src/cli.ts", "detect", path.join(fixtures, "flutter")], {
    cwd: path.join(fixtures, ".."),
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /flutter/);
});
