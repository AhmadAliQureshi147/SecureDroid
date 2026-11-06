import fs from "node:fs";
import path from "node:path";
import { collectFiles } from "./analysis.ts";
import { languageOf } from "./detect.ts";
import { findingsForFile } from "./rules.ts";
import type { SourceFile } from "./types.ts";

const PAGE_CHARS = 8_000;

interface Piece {
  path: string;
  language: string;
  text: string;
  part: number;
  parts: number;
}

const AUDIT_CHARS = 160_000;

export function readSourcePage(root: string, pageNumber: number): string {
  const collected = collectFiles(root);
  const pages = pack(splitFiles(collected.files));
  if (pages.length === 0) return "No source files were collected. SecureDroid reads Kotlin, Java, C, C++, C#, Dart, JavaScript, TypeScript, Python, Rust, Ruby, Lua, HTML, CSS, Groovy, Gradle, and XML.";
  const page = Number.isFinite(pageNumber) && pageNumber > 0 ? Math.floor(pageNumber) : 1;
  if (page > pages.length) {
    return `Page ${page} is past the end. There are ${pages.length} source pages. Every collected directory has been shown.`;
  }
  return renderPage(root, collected.files, collected.truncated, pages, page, "page");
}

export function readSourceBundle(root: string): { text: string; pages: number; included: number } {
  const collected = collectFiles(root);
  const pages = pack(splitFiles(collected.files));
  if (pages.length === 0) {
    return {
      text: "No source files were collected. SecureDroid reads Kotlin, Java, C, C++, C#, Dart, JavaScript, TypeScript, Python, Rust, Ruby, Lua, HTML, CSS, Groovy, Gradle, and XML.",
      pages: 0,
      included: 0,
    };
  }
  const chunks: string[] = [];
  let used = 0;
  let included = 0;
  for (let index = 0; index < pages.length; index += 1) {
    const pageText = renderPage(root, collected.files, collected.truncated, pages, index + 1, "bundle");
    if (included > 0 && used + pageText.length > AUDIT_CHARS) break;
    chunks.push(pageText);
    used += pageText.length;
    included += 1;
  }
  const left = pages.length - included;
  const cover =
    left === 0
      ? `Source context: all ${pages.length} directories are below. Judge this source, then give the end result.`
      : `Source context: directories 1-${included} of ${pages.length} are below. Call action read for page ${included + 1} through ${pages.length} before the end result.`;
  return { text: [cover, ...chunks].join("\n\n"), pages: pages.length, included };
}

function renderPage(root: string, files: SourceFile[], truncated: boolean, pages: Piece[][], page: number, mode: "page" | "bundle"): string {
  const current = pages[page - 1] ?? [];
  const directory = directoryOf(current[0]?.path ?? "");
  const languages = [...new Set(current.map((piece) => piece.language))].join(", ");
  const last = page === pages.length;
  const nextStep =
    mode === "bundle"
      ? "This directory is part of the one-pass context. Judge every line here before the end result."
      : last
        ? "This is the last page. Review this directory for insecure Android code before you finish. Every collected directory has been shown."
        : `Review this directory for insecure Android code before the next page. Then call android_security action read with page "${page + 1}".`;
  return [
    `Source page ${page} of ${pages.length}. Directory: ${directory}. Languages: ${languages}.`,
    nextStep,
    truncated ? "Some files were skipped because the project exceeded the file count or the per-file size limit." : "",
    "While you read the lines below, first understand what this directory does in the app. Then review them for insecure Android coding in Kotlin, Java, C, C++, C#, Dart, JavaScript, TypeScript, Python, Rust, Ruby, Lua, HTML, CSS, Groovy, and XML. Use the rules and your own insecure-coding knowledge on every line. The code map is only the wiring.",
    rulesOnPage(files, current.map((piece) => piece.path)),
    directoryLinks(root, directory),
    "Go line by line. If the rules already recorded a line, leave it and continue to the next line. If your Android knowledge says a line is insecure and the rules missed it, call action record for that file and line, then continue to the next line. Do not stop the directory. Do not invent a line, and do not write an exploit.",
    "A fix is staged for the developer to accept. Do not edit the file. Keep the same screen, data, and user step. If the safe fix would change how the app behaves, leave a recommendation.",
    current.map(formatPiece).join("\n\n"),
  ]
    .filter((line) => line.length > 0)
    .join("\n\n");
}

export function linksForDirectory(
  graph: { nodes?: Array<{ id?: string; label?: string; source_file?: string }>; edges?: Array<{ source?: string; target?: string; relation?: string; confidence?: string; source_file?: string }> },
  directory: string,
): string {
  const prefix = directory === "." ? "" : `${directory}/`;
  const inDir = (file: string | undefined) => (directory === "." ? Boolean(file && !file.includes("/")) : Boolean(file?.startsWith(prefix)));
  const labels = new Map((graph.nodes ?? []).map((node) => [node.id ?? "", node.label ?? node.id ?? ""]));
  const lines = (graph.edges ?? [])
    .filter((edge) => inDir(edge.source_file))
    .slice(0, 8)
    .map((edge) => `- ${labels.get(edge.source ?? "") || edge.source} ${edge.relation ?? "links"} ${labels.get(edge.target ?? "") || edge.target} [${edge.confidence ?? "unknown"}]`);
  if (lines.length === 0) return "Code map for this directory: no links yet. Judge the source itself.";
  return ["Code map for this directory, read it with the source:", ...lines].join("\n");
}

function rulesOnPage(files: SourceFile[], pagePaths: string[]): string {
  const wanted = new Set(pagePaths);
  const lines = new Set<string>();
  for (const file of files) {
    if (!wanted.has(file.path)) continue;
    for (const finding of findingsForFile(file, files)) {
      lines.add(`- ${finding.ruleId} ${finding.path}:${finding.line}`);
    }
  }
  const listed = [...lines].slice(0, 12);
  if (listed.length === 0) return "Rules recorded nothing on this page. Judge every line with your own Android insecure-coding knowledge.";
  const more = lines.size > listed.length ? "More rule hits exist on this page. Keep going line by line for anything not listed." : "";
  return ["Rules already recorded these lines. Do not record them again:", ...listed, more].filter((line) => line.length > 0).join("\n");
}

function directoryOf(filePath: string): string {
  const directory = path.posix.dirname(filePath);
  return directory === "." ? "." : directory;
}

function directoryLinks(root: string, directory: string): string {
  const graphPath = path.join(root, ".secure-droid", "graphify-out", "graph.json");
  if (!fs.existsSync(graphPath)) return "Code map for this directory: not built yet. Judge the source with your Android secure-coding knowledge.";
  try {
    return linksForDirectory(JSON.parse(fs.readFileSync(graphPath, "utf8")) as Parameters<typeof linksForDirectory>[0], directory);
  } catch {
    return "Code map for this directory: unreadable. Judge the source itself.";
  }
}

function splitFiles(files: SourceFile[]): Piece[] {
  const pieces: Piece[] = [];
  for (const file of files) {
    const text = redactForReading(file.text);
    const parts = Math.max(1, Math.ceil(text.length / PAGE_CHARS));
    for (let index = 0; index < parts; index += 1) {
      pieces.push({
        path: file.path,
        language: languageOf(file.path) ?? "xml",
        text: text.slice(index * PAGE_CHARS, (index + 1) * PAGE_CHARS),
        part: index + 1,
        parts,
      });
    }
  }
  return pieces;
}

function pack(pieces: Piece[]): Piece[][] {
  const pages: Piece[][] = [];
  let current: Piece[] = [];
  let size = 0;
  let directory = "";
  for (const piece of pieces) {
    const nextDirectory = directoryOf(piece.path);
    const directoryChanged = current.length > 0 && nextDirectory !== directory;
    if (current.length > 0 && (directoryChanged || size + piece.text.length > PAGE_CHARS)) {
      pages.push(current);
      current = [];
      size = 0;
    }
    directory = nextDirectory;
    current.push(piece);
    size += piece.text.length;
  }
  if (current.length > 0) pages.push(current);
  return pages;
}

function formatPiece(piece: Piece): string {
  const part = piece.parts > 1 ? `, part ${piece.part} of ${piece.parts}` : "";
  return `### ${piece.path} (${piece.language}${part})\n${piece.text}`;
}

function redactForReading(text: string): string {
  return text
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "<redacted-private-key>")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "<redacted>")
    .replace(/\bAIza[0-9A-Za-z\-_]{35}\b/g, "<redacted>")
    .replace(/((?:password|passwd|secret|api[_-]?key|access[_-]?token)\s*[=:]\s*)(["'])[^"'\n]{8,}\2/gi, "$1$2<redacted>$2");
}
