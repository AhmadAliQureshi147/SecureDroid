export const SEVERITIES = ["P0", "P1", "P2", "P3", "informational"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CONFIDENCE = ["confirmed", "high", "medium", "low"] as const;
export type Confidence = (typeof CONFIDENCE)[number];

export const STATUSES = ["open", "mitigated", "suppressed", "staged", "fixed"] as const;
export type FindingStatus = (typeof STATUSES)[number];

export type Language =
  | "kotlin"
  | "java"
  | "c"
  | "cpp"
  | "csharp"
  | "xml"
  | "gradle"
  | "groovy"
  | "dart"
  | "javascript"
  | "typescript"
  | "python"
  | "rust"
  | "ruby"
  | "lua"
  | "html"
  | "css";

export type Category =
  | "authentication"
  | "authorization"
  | "storage"
  | "cryptography"
  | "network"
  | "platform"
  | "webview"
  | "injection"
  | "privacy"
  | "build"
  | "dependencies"
  | "resilience";

export type DetectionMethod = "pattern" | "config" | "cross-file" | "llm-investigation";
export type RuntimeExposure = "runtime-reachable" | "runtime-conditional" | "build-time";

export type Recipe = "automatic" | "manual";

export interface Evidence {
  path: string;
  line: number;
  description: string;
}

export interface VerificationCheck {
  name: string;
  status: "not-run" | "passed" | "failed" | "partial" | "blocked";
  detail: string;
}

export interface Verification {
  status: "not-run" | "passed" | "failed" | "partial" | "blocked";
  checks: VerificationCheck[];
}

export interface Finding {
  id: string;
  title: string;
  language: Language;
  path: string;
  line: number;
  severity: Severity;
  confidence: Confidence;
  category: Category;
  ruleId: string;
  detectionMethods: DetectionMethod[];
  evidence: Evidence[];
  attackScenario: string;
  preconditions: string[];
  why: string;
  recommendation: string;
  recipe: Recipe;
  runtime: { exposure: RuntimeExposure; summary: string };
  verification: Verification;
  status: FindingStatus;
  fingerprint: string;
  masvs: string[];
  verdict?: { result: "upheld" | "withheld" | "rejected"; reason: string };
  subject?: string;
  updatedAt: string;
}

export interface ExceptionRecord {
  findingId: string;
  ruleId: string;
  path: string;
  fingerprint: string;
  reason: string;
  createdAt: string;
  reviewer?: string;
}

export interface SourceFile {
  path: string;
  text: string;
}

export interface Draft {
  ruleId: string;
  title: string;
  language: Language;
  path: string;
  line: number;
  severity: Severity;
  confidence: Confidence;
  category: Category;
  detectionMethods: DetectionMethod[];
  evidence: Evidence[];
  attackScenario: string;
  preconditions: string[];
  why: string;
  recommendation: string;
  recipe: Recipe;
  masvs: string[];
  subject?: string;
  fingerprintSource: string;
}

export interface ManifestComponent {
  kind: "activity" | "service" | "receiver" | "provider";
  name: string;
  exported: boolean | "unspecified";
  permission?: string;
  grantUriPermissions: boolean;
  actions: string[];
  categories: string[];
  line: number;
}

export interface ParsedManifest {
  path: string;
  packageName?: string;
  debuggable: boolean;
  allowBackup: boolean;
  usesCleartextTraffic: boolean;
  networkSecurityConfig?: string;
  components: ManifestComponent[];
}

export interface Detection {
  isAndroid: boolean;
  frameworks: string[];
  languages: Language[];
  modules: string[];
  tools: Record<string, boolean>;
  limitations: string[];
}

export interface ProjectMap {
  root: string;
  frameworks: string[];
  languages: Language[];
  filesScanned: number;
  manifests: ParsedManifest[];
  modules: string[];
  entryPoints: Array<{
    kind: string;
    name: string;
    path: string;
    line: number;
    exported: boolean | "unspecified";
  }>;
  limitations: string[];
}

export interface ReviewDecision {
  decision: "ready" | "needs-review" | "blocked" | "recommendation-only";
  reasons: string[];
}

export interface StagedChange {
  findingId: string;
  path: string;
  baseHash: string;
  recipe: Recipe;
  kind: "patch" | "recommendation";
  diff: string;
  patched?: string;
  review: ReviewDecision;
  verification: Verification;
  createdAt: string;
}

export interface StoreData {
  version: 1;
  findings: Finding[];
  exceptions: ExceptionRecord[];
  staged: StagedChange[];
}

export const EMPTY_VERIFICATION: Verification = { status: "not-run", checks: [] };
