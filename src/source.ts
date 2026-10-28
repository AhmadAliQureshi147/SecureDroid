import { collectFiles } from "./analysis.ts";
import { languageOf } from "./detect.ts";
import type { SourceFile } from "./types.ts";

const PAGE_CHARS = 8_000;

interface Piece {
  path: string;
  language: string;
  text: string;
  part: number;
  parts: number;
}

export function readSourcePage(root: string, pageNumber: number): string {
  const collected = collectFiles(root);
  const pages = pack(splitFiles(collected.files));
  if (pages.length === 0) return "No source files were collected. SecureDroid reads Kotlin, Java, Dart, JavaScript, TypeScript, XML, and Gradle.";
  const page = Number.isFinite(pageNumber) && pageNumber > 0 ? Math.floor(pageNumber) : 1;
  if (page > pages.length) {
    return `Page ${page} is past the end. There are ${pages.length} source pages. Every collected file has been shown.`;
  }
  const current = pages[page - 1] ?? [];
  const languages = [...new Set(current.map((piece) => piece.language))].join(", ");
  const last = page === pages.length;
  return [
    `Source page ${page} of ${pages.length}. Languages on this page: ${languages}.`,
    last
      ? "This is the last page. Every collected source file has been shown. Do not call the review finished before this page."
      : `Call android_security action read with page "${page + 1}" before you finish the review.`,
    collected.truncated ? "Some files were skipped because the project exceeded the file count or the per-file size limit." : "",
    "Read the code below. This pass is for Kotlin, Java, Jetpack Compose, Flutter/Dart, and React Native JavaScript or TypeScript, plus manifests and Gradle.",
    "Look for weak Android coding on the lines in front of you: TLS and cleartext, WebView settings, exported components, storage, crypto, secrets, injection, and dynamic code. Record a real line the rules missed. Do not invent a line, and do not write an exploit.",
    current.map(formatPiece).join("\n\n"),
  ]
    .filter((line) => line.length > 0)
    .join("\n\n");
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
  for (const piece of pieces) {
    if (current.length > 0 && size + piece.text.length > PAGE_CHARS) {
      pages.push(current);
      current = [];
      size = 0;
    }
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
