export function checkFileSyntax(text: string): { status: "passed" | "failed"; detail: string } {
  const stack: string[] = [];
  let index = 0;
  let line = 1;
  let quote: string | null = null;
  while (index < text.length) {
    const char = text[index] ?? "";
    const next = text[index + 1] ?? "";
    if (char === "\n") line += 1;
    if (quote === '"""') {
      if (text.startsWith('"""', index)) {
        quote = null;
        index += 3;
        continue;
      }
      index += 1;
      continue;
    }
    if (quote) {
      if (char === "\\") {
        index += 2;
        continue;
      }
      if (char === quote) quote = null;
      index += 1;
      continue;
    }
    if (char === "/" && next === "/") {
      while (index < text.length && text[index] !== "\n") index += 1;
      continue;
    }
    if (char === "/" && next === "*") {
      index += 2;
      while (index < text.length && !(text[index] === "*" && text[index + 1] === "/")) {
        if (text[index] === "\n") line += 1;
        index += 1;
      }
      index += 2;
      continue;
    }
    if (text.startsWith('"""', index)) {
      quote = '"""';
      index += 3;
      continue;
    }
    if (char === '"' || char === "'" || char === "`") {
      quote = char;
      index += 1;
      continue;
    }
    if (char === "(" || char === "{" || char === "[") stack.push(char);
    if (char === ")" || char === "}" || char === "]") {
      const open = stack.pop();
      const expected = char === ")" ? "(" : char === "}" ? "{" : "[";
      if (open !== expected) return { status: "failed", detail: `Delimiter mismatch at line ${line}.` };
    }
    index += 1;
  }
  if (quote) return { status: "failed", detail: "A string is still open at the end of the patched file." };
  if (stack.length > 0) return { status: "failed", detail: "The patched file has an unclosed delimiter." };
  return {
    status: "passed",
    detail: "The patched file has balanced delimiters. Project Gradle was not run.",
  };
}
