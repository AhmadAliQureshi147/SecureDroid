#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { runSecureDroid } from "./engine.ts";

const [command = "help", ...rest] = process.argv.slice(2);
const needsId = new Set(["investigate", "explain", "recommend", "fix", "verify", "accept", "reject", "except", "thread"]);

function help(): string {
  return [
    "SecureDroid — Android security agent",
    "",
    "  securedroid detect [root]",
    "  securedroid map [root]",
    "  securedroid scan [root]",
    "  securedroid review [root]",
    "  securedroid read [page] [root]",
    "  securedroid findings [root]",
    "  securedroid threads [root]",
    "  securedroid thread <thread-id> [root]",
    "  securedroid activity [root]",
    "  securedroid baseline [root]",
    "  securedroid investigate <finding-id> [root]",
    "  securedroid fix <finding-id> [root]",
    "  securedroid remediate [root]",
    "  securedroid verify <finding-id> [root]",
    "  securedroid accept <finding-id> [root]",
    "  securedroid reject <finding-id> [root]",
    "  securedroid except <finding-id> <reason> [root]",
    "",
    "Load the same engine in Oh My Pi with: omp --extension <this-directory>",
  ].join("\n");
}

function split(args: string[]): { findingId?: string; reason?: string; root: string } {
  if (command === "read") {
    const pageFirst = /^\d+$/.test(args[0] ?? "");
    return { reason: pageFirst ? args[0] : "1", root: path.resolve((pageFirst ? args[1] : args[0]) ?? process.cwd()) };
  }
  if (!needsId.has(command)) {
    return { root: path.resolve(args[0] ?? process.cwd()) };
  }
  if (command === "except") {
    const findingId = args[0];
    const maybeRoot = args.at(-1);
    const hasRoot = args.length >= 3 && maybeRoot !== undefined && fs.existsSync(maybeRoot) && fs.statSync(maybeRoot).isDirectory();
    const reasonParts = hasRoot ? args.slice(1, -1) : args.slice(1);
    return {
      findingId,
      reason: reasonParts.join(" "),
      root: path.resolve(hasRoot && maybeRoot ? maybeRoot : process.cwd()),
    };
  }
  const findingId = args[0];
  return { findingId, root: path.resolve(args[1] ?? process.cwd()) };
}

if (command === "help" || command === "--help" || command === "-h") {
  console.log(help());
} else {
  const parsed = split(rest);
  const result = runSecureDroid({
    action: command === "findings" ? "status" : command,
    root: parsed.root,
    findingId: parsed.findingId,
    reason: parsed.reason,
    page: command === "read" ? parsed.reason : undefined,
  });
  console.log(result.text);
  if (!result.ok) process.exitCode = 1;
}
