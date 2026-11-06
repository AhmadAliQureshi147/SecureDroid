import { spawnSync } from "node:child_process";
import { graphifyInstalled } from "./graphify.ts";
import { resolveTool } from "./tools.ts";
import type { Detection, Language, SourceFile } from "./types.ts";

const SOURCE_EXTENSIONS = new Set([
  ".kt",
  ".java",
  ".c",
  ".cc",
  ".cpp",
  ".cxx",
  ".h",
  ".hh",
  ".hpp",
  ".hxx",
  ".cs",
  ".xml",
  ".gradle",
  ".kts",
  ".groovy",
  ".dart",
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".py",
  ".rs",
  ".rb",
  ".lua",
  ".html",
  ".htm",
  ".css",
  ".yaml",
  ".yml",
  ".toml",
  ".properties",
]);

export function languageOf(filePath: string): Language | undefined {
  if (filePath.endsWith(".gradle.kts") || filePath.endsWith(".gradle")) return "gradle";
  if (filePath.endsWith(".groovy")) return "groovy";
  if (filePath.endsWith(".kt") || filePath.endsWith(".kts")) return "kotlin";
  if (filePath.endsWith(".java")) return "java";
  if (filePath.endsWith(".c")) return "c";
  if (/\.(cc|cpp|cxx|h|hh|hpp|hxx)$/.test(filePath)) return "cpp";
  if (filePath.endsWith(".cs")) return "csharp";
  if (filePath.endsWith(".xml")) return "xml";
  if (filePath.endsWith(".dart")) return "dart";
  if (filePath.endsWith(".ts") || filePath.endsWith(".tsx")) return "typescript";
  if (filePath.endsWith(".js") || filePath.endsWith(".jsx")) return "javascript";
  if (filePath.endsWith(".py")) return "python";
  if (filePath.endsWith(".rs")) return "rust";
  if (filePath.endsWith(".rb")) return "ruby";
  if (filePath.endsWith(".lua")) return "lua";
  if (filePath.endsWith(".html") || filePath.endsWith(".htm")) return "html";
  if (filePath.endsWith(".css")) return "css";
  return undefined;
}

export function isSourcePath(filePath: string): boolean {
  const base = filePath.slice(filePath.lastIndexOf("/") + 1);
  if (base === "package.json" || base === "pubspec.yaml" || base === "pubspec.yml") return true;
  if (base.endsWith(".gradle.kts")) return true;
  const dot = base.lastIndexOf(".");
  if (dot < 0) return false;
  return SOURCE_EXTENSIONS.has(base.slice(dot));
}

function hasBinary(name: string): boolean {
  const result = spawnSync("which", [name], { encoding: "utf8" });
  return result.status === 0;
}

export function availableTools(): Record<string, boolean> {
  return {
    "ast-grep": resolveTool("ast-grep") !== undefined,
    semgrep: resolveTool("semgrep") !== undefined,
    java: hasBinary("java"),
    gradle: hasBinary("gradle"),
    dart: hasBinary("dart"),
    flutter: hasBinary("flutter"),
    node: hasBinary("node"),
  };
}

export function detectFromFiles(files: SourceFile[], tools = availableTools()): Detection {
  const joinedPaths = files.map((file) => file.path).join("\n");
  const gradle = files.filter((file) => file.path.endsWith(".gradle") || file.path.endsWith(".gradle.kts"));
  const manifests = files.filter((file) => file.path.endsWith("AndroidManifest.xml"));
  const packageJson = files.find((file) => file.path.endsWith("package.json") && !file.path.includes("node_modules"));
  const pubspec = files.find((file) => /(^|\/)pubspec\.ya?ml$/.test(file.path));
  const languages = new Set<Language>();
  for (const file of files) {
    const language = languageOf(file.path);
    if (language) languages.add(language);
  }

  const frameworks: string[] = [];
  const native = manifests.length > 0 || gradle.some((file) => /com\.android\.(application|library)/.test(file.text));
  if (native) frameworks.push("native-android");
  const compose =
    gradle.some((file) => /compose|androidx\.compose/.test(file.text)) ||
    files.some((file) => /androidx\.compose/.test(file.text));
  if (compose) frameworks.push("compose");
  const flutter = Boolean(pubspec && /sdk:\s*flutter|\bflutter\s*:/.test(pubspec.text));
  if (flutter) frameworks.push("flutter");
  let reactNative = false;
  if (packageJson) {
    try {
      const parsed = JSON.parse(packageJson.text) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
      reactNative = Boolean(parsed.dependencies?.["react-native"] || parsed.devDependencies?.["react-native"]);
    } catch {
      reactNative = /"react-native"/.test(packageJson.text);
    }
  }
  if (reactNative) frameworks.push("react-native");

  const modules = [
    ...new Set(
      gradle
        .map((file) => file.path.replace(/\/[^/]+$/, ""))
        .filter((dir) => dir.length > 0),
    ),
  ];

  const limitations = [
    "SecureDroid does not claim complete MASVS coverage. masvs on a finding names the requirement the implemented check relates to.",
    "Dependency versions are compared with a local OSV snapshot. A package missing from that snapshot is not a pass.",
    "Semgrep is required. A scan without it is incomplete. The Sigma and YARA packs in engines/ run on every scan.",
    "ast-grep is an extra structural scanner. A missing ast-grep is unavailable, not a pass.",
  ];
  if (!tools["ast-grep"]) limitations.push("ast-grep is not installed. Structural checks use SecureDroid patterns and Oh My Pi's ast_grep tool when that session is running.");
  if (!tools.semgrep) limitations.push("Required scanner semgrep is not installed. This scan is incomplete. The engines/semgrep pack did not run.");
  if (!tools.java) limitations.push("Java is not installed. Android Lint and compilation were not run.");

  return {
    isAndroid: frameworks.length > 0 || manifests.length > 0 || /AndroidManifest\.xml/.test(joinedPaths),
    frameworks,
    languages: [...languages],
    modules,
    tools,
    limitations,
  };
}
