import path from "node:path";
import { runSecureDroid } from "./engine.ts";
import { guardToolCall } from "./guard.ts";
import { SECURITY_POLICY } from "./policy.ts";
import { collectFiles } from "./analysis.ts";
import { detectFromFiles } from "./detect.ts";

interface ZodString {
  describe(text: string): ZodString;
  optional(): ZodString;
}

interface HostContext {
  cwd?: string;
  ui?: { notify(message: string, level?: string): void };
}

interface HostEvent {
  systemPrompt?: string[];
  reason?: string;
  toolName?: string;
  input?: Record<string, unknown>;
}

interface HostApi {
  zod: {
    object(shape: Record<string, unknown>): unknown;
    string(): ZodString;
    enum(values: readonly string[]): unknown;
  };
  setLabel(label: string): void;
  on(event: string, handler: (event: HostEvent, ctx: HostContext) => unknown): void;
  registerTool(tool: {
    name: string;
    label: string;
    description: string;
    parameters: unknown;
    approval?: string;
    loadMode?: string;
    execute: (toolCallId: string, params: Record<string, unknown>, signal: AbortSignal, onUpdate: unknown, ctx: HostContext) => Promise<unknown>;
  }): void;
  registerCommand(name: string, command: { description: string; handler: (args: string, ctx: HostContext) => Promise<void> | void }): void;
  sendMessage(message: { customType: string; content: string; display: boolean }): void;
  sendUserMessage(content: string): void;
}

const TOOL_ACTIONS = ["detect", "map", "scan", "review", "read", "triage", "investigate", "explain", "recommend", "fix", "remediate", "verify", "judge", "status", "record"] as const;

const detectedProjects = new Map<string, boolean>();

function projectIsAndroid(cwd: string): boolean {
  const cached = detectedProjects.get(cwd);
  if (cached !== undefined) return cached;
  const detected = detectFromFiles(collectFiles(cwd).files).isAndroid;
  detectedProjects.set(cwd, detected);
  return detected;
}

function emit(pi: HostApi, ctx: HostContext, text: string): void {
  const summary = text.split("\n")[0] ?? "SecureDroid";
  ctx.ui?.notify(summary.slice(0, 240), "info");
  pi.sendMessage({ customType: "securedroid", content: text, display: true });
}

export default function secureDroid(pi: HostApi): void {
  const z = pi.zod;
  pi.setLabel("SecureDroid");

  pi.on("session_start", (_event, ctx) => {
    const cwd = ctx.cwd || process.cwd();
    if (projectIsAndroid(cwd)) ctx.ui?.notify("SecureDroid: Android project detected", "info");
  });

  pi.on("before_agent_start", (event, ctx) => {
    if (event.reason === "revive") return undefined;
    const cwd = ctx.cwd || process.cwd();
    if (!projectIsAndroid(cwd)) return undefined;
    return { systemPrompt: [...(event.systemPrompt ?? []), SECURITY_POLICY] };
  });

  pi.on("tool_call", (event) => {
    if (!event.toolName || !event.input) return undefined;
    const decision = guardToolCall(event.toolName, event.input);
    if (decision.block) return { block: true, reason: decision.reason };
    return undefined;
  });

  pi.registerTool({
    name: "android_security",
    label: "Android security",
    description:
      "Android security harness for Kotlin, Java, Compose, Flutter, React Native, manifests, and Gradle. detect, map, scan, then read every source page before judging. triage, investigate, explain, record a line-pinned finding, judge a finding, and stage fixes with fix or remediate. Only upheld findings are vulnerabilities. This tool does not apply patches; the developer accepts them.",
    loadMode: "essential",
    approval: "write",
    parameters: z.object({
      action: z.enum(TOOL_ACTIONS),
      findingId: z.string().describe("Finding id for investigate, explain, recommend, fix, or verify").optional(),
      path: z.string().describe("Repository root. Defaults to the session workspace.").optional(),
      file: z.string().describe("Repository-relative source file for action record.").optional(),
      line: z.string().describe("1-based source line for action record.").optional(),
      title: z.string().describe("Short title for action record.").optional(),
      why: z.string().describe("Why the recorded line is a problem, or the verifier note for action judge.").optional(),
      recommendation: z.string().describe("Fix recommendation for action record.").optional(),
      category: z.string().describe("Finding category for action record.").optional(),
      severity: z.string().describe("P1, P2, P3, or informational. P0 is rejected.").optional(),
      masvs: z.string().describe("Optional MASVS v2 requirement id for action record.").optional(),
      decision: z.string().describe("For action judge: uphold or reject.").optional(),
      page: z.string().describe("1-based source page for action read. Start at 1 and continue until the last page.").optional(),
    }),
    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      const base = ctx.cwd || process.cwd();
      const root = path.resolve(base, typeof params.path === "string" && params.path.length > 0 ? params.path : ".");
      const text = (value: unknown) => (typeof value === "string" ? value : undefined);
      const result = runSecureDroid({
        action: String(params.action),
        root,
        findingId: text(params.findingId),
        file: text(params.file),
        line: text(params.line),
        title: text(params.title),
        why: text(params.why),
        recommendation: text(params.recommendation),
        category: text(params.category),
        severity: text(params.severity),
        masvs: text(params.masvs),
        decision: text(params.decision),
        page: text(params.page),
      });
      return {
        content: [{ type: "text", text: result.text }],
        details: result.data ?? { ok: result.ok },
        isError: !result.ok,
      };
    },
  });

  const commands: Array<{ name: string; description: string; run: (args: string, cwd: string) => { text: string; user?: string } }> = [
    { name: "android-detect", description: "Identify Android frameworks, languages, and available tools", run: (_args, cwd) => ({ text: runSecureDroid({ action: "detect", root: cwd }).text }) },
    { name: "android-map", description: "Map Android entry points and modules", run: (_args, cwd) => ({ text: runSecureDroid({ action: "map", root: cwd }).text }) },
    { name: "android-scan", description: "Run deterministic Android security checks", run: (_args, cwd) => ({ text: runSecureDroid({ action: "scan", root: cwd }).text }) },
    { name: "android-triage", description: "Keep only verifier-upheld vulnerabilities", run: (_args, cwd) => ({ text: runSecureDroid({ action: "triage", root: cwd }).text }) },
    { name: "android-findings", description: "Show stored SecureDroid findings", run: (_args, cwd) => ({ text: runSecureDroid({ action: "status", root: cwd }).text }) },
    {
      name: "android-review",
      description: "Scan and ask the model to investigate the Android project",
      run: (_args, cwd) => ({
        text: runSecureDroid({ action: "review", root: cwd }).text,
        user: "Review this Android project before production. Call android_security action read from page 1 until the last page and read the Kotlin, Java, Flutter, and React Native source. Record weak coding on a real line the rules missed, then spawn android-verifier. Report only upheld findings. Do not modify source files.",
      }),
    },
    { name: "android-investigate", description: "Show evidence for one finding", run: (args, cwd) => ({ text: runSecureDroid({ action: "investigate", root: cwd, findingId: args.trim() }).text }) },
    { name: "android-fix", description: "Stage a remediation without modifying source", run: (args, cwd) => ({ text: runSecureDroid({ action: "fix", root: cwd, findingId: args.trim() }).text }) },
    { name: "android-remediate", description: "Stage every automatic fix and leave source unchanged", run: (_args, cwd) => ({ text: runSecureDroid({ action: "remediate", root: cwd }).text }) },
    { name: "android-verify", description: "Re-check a staged remediation", run: (args, cwd) => ({ text: runSecureDroid({ action: "verify", root: cwd, findingId: args.trim() }).text }) },
    { name: "android-accept", description: "Save a staged patch that is not blocked", run: (args, cwd) => ({ text: runSecureDroid({ action: "accept", root: cwd, findingId: args.trim() }).text }) },
    { name: "android-reject", description: "Discard a staged patch and leave source unchanged", run: (args, cwd) => ({ text: runSecureDroid({ action: "reject", root: cwd, findingId: args.trim() }).text }) },
    {
      name: "android-except",
      description: "Record a fingerprint-scoped exception",
      run: (args, cwd) => {
        const [findingId, ...reason] = args.trim().split(/\s+/);
        return { text: runSecureDroid({ action: "except", root: cwd, findingId, reason: reason.join(" ") }).text };
      },
    },
  ];

  for (const command of commands) {
    pi.registerCommand(command.name, {
      description: command.description,
      handler: async (args, ctx) => {
        const cwd = ctx.cwd || process.cwd();
        const result = command.run(args, cwd);
        emit(pi, ctx, result.text);
        if (result.user) pi.sendUserMessage(result.user);
      },
    });
  }
}
