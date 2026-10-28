import { spawnSync } from "node:child_process";
import { resolveTool } from "./tools.ts";
import type { Detection, Language, SourceFile } from "./types.ts";

const SOURCE_EXTENSIONS = new Set([
  ".kt",
  ".java",
  ".xml",
  ".gradle",
  ".kts",
  ".dart",
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".yaml",
  ".yml",
  ".toml",
  ".properties",
]);

export function languageOf(filePath: string): Language | undefined {
  if (filePath.endsWith(".kt") || filePath.endsWith(".kts")) return "kotlin";
  if (filePath.endsWith(".java")) return "java";
  if (filePath.endsWith(".xml")) return "xml";
  if (filePath.endsWith(".gradle")) return "gradle";
  if (filePath.endsWith(".dart")) return "dart";
  if (filePath.endsWith(".ts") || filePath.endsWith(".tsx")) return "typescript";
  if (filePath.endsWith(".js") || filePath.endsWith(".jsx")) return "javascript";
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
    "Dependency versions are inventoried only. They are not compared with a vulnerability database.",
    "Optional analyzers that are not installed are reported as unavailable and are not treated as passed.",
  ];
  if (!tools["ast-grep"]) limitations.push("ast-grep is not installed. Structural checks use SecureDroid patterns and Oh My Pi's ast_grep tool when that session is running.");
  if (!tools.semgrep) limitations.push("semgrep is not installed. The engines/semgrep ruleset was not executed.");
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
