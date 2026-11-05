import { dependencyFindings } from "./advisories.ts";
import type { Confidence, Draft, Evidence, Language, Severity, SourceFile } from "./types.ts";
import { languageOf } from "./detect.ts";
import { isLauncher, onlyProtectedBroadcasts, parseManifest } from "./manifest.ts";
import { requirementIds } from "./standards.ts";
import { lineAt, lineText, redact, sha256 } from "./text.ts";

const AUTH_MARKERS =
  /checkCallingOrSelfPermission|checkCallingPermission|checkSelfPermission|enforceCallingPermission|enforceCallingOrSelfPermission|getCallingUid|getCallingPackage|Binder\.getCallingUid/;

function draft(partial: Draft): Draft {
  return { ...partial, masvs: requirementIds(partial.ruleId) };
}

function evidence(path: string, line: number, description: string): Evidence {
  return { path, line, description: redact(description) };
}

function severityAtLeast(current: Severity, next: Severity): Severity {
  const rank: Record<Severity, number> = { P0: 0, P1: 1, P2: 2, P3: 3, informational: 4 };
  return rank[next] < rank[current] ? next : current;
}

function matchesIn(text: string, pattern: RegExp): Array<{ index: number; line: number; snippet: string }> {
  return [...text.matchAll(pattern)].map((match) => {
    const index = match.index ?? 0;
    const line = lineAt(text, index);
    return { index, line, snippet: lineText(text, line).trim() };
  });
}

function releaseBlock(text: string): string {
  const start = /\brelease\s*\{/.exec(text);
  if (!start || start.index === undefined) return "";
  let depth = 0;
  for (let i = start.index; i < text.length; i++) {
    if (text[i] === "{") depth += 1;
    if (text[i] === "}") {
      depth -= 1;
      if (depth === 0) return text.slice(start.index, i + 1);
    }
  }
  return "";
}

function scanSecrets(file: SourceFile, language: Language): Draft[] {
  if (language === "gradle" || file.path.endsWith(".gradle.kts")) return [];
  const found: Draft[] = [];
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(file.text)) {
    const line = lineAt(file.text, file.text.indexOf("-----BEGIN"));
    found.push(
      draft({
        ruleId: "SECRET-PRIVATE-KEY",
        title: "Private key embedded in source",
        language,
        path: file.path,
        line,
        severity: "P0",
        confidence: "confirmed",
        category: "storage",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, line, "A PEM private key block is present in this file.")],
        attackScenario:
          "Anyone who obtains the application source or the shipped artifact can extract the embedded key.",
        preconditions: ["The key material is the real private key and not a public sample marker."],
        why: "Private keys stored in the repository are copied into builds, backups, and developer machines.",
        recommendation:
          "Remove the key from source, rotate it, and load future key material from the platform keystore or a deployment secret store.",
        recipe: "manual",
        masvs: ["MASVS-STORAGE"],
        fingerprintSource: sha256(file.text.match(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/)?.[0] ?? "private-key").slice(0, 16),
      }),
    );
  }

  const assignment =
    /(?:const\s+val|val|var|final\s+String|String|const)\s+([A-Za-z0-9_]*(?:password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)[A-Za-z0-9_]*)\s*=\s*(["'])([^"'\n]{8,})\2/gi;
  for (const match of file.text.matchAll(assignment)) {
    const line = lineAt(file.text, match.index ?? 0);
    const snippet = lineText(file.text, line);
    if (/Log\.[dview]\s*\(/.test(snippet)) continue;
    const value = match[3] ?? "";
    const placeholder = /^(password|secret|changeme|change_me|todo|placeholder|your[-_ ]?api[-_ ]?key|xxx+|insert|example|test|fake|session)$/i.test(
      value,
    );
    const inTest = /\/(test|androidTest)\//.test(file.path);
    found.push(
      draft({
        ruleId: "SECRET-HARDCODED",
        title: placeholder || inTest ? "Possible credential placeholder" : "Hardcoded credential",
        language,
        path: file.path,
        line,
        severity: placeholder || inTest ? "informational" : "P1",
        confidence: placeholder || inTest ? "low" : "high",
        category: "storage",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, line, "A credential-like name is assigned a literal.")],
        attackScenario:
          "If the literal is a real credential, anyone with the source or the artifact can reuse it.",
        preconditions: ["The literal is a live secret rather than a placeholder or test value."],
        why: "Hardcoded credentials cannot be rotated without shipping a new build.",
        recommendation: "Remove the literal, rotate the credential if it was real, and read it from a secret store or user input.",
        recipe: "manual",
        masvs: ["MASVS-STORAGE"],
        subject: match[1],
        fingerprintSource: `${match[1]}:${sha256(value).slice(0, 12)}`,
      }),
    );
  }
  return found;
}

function scanSource(file: SourceFile): Draft[] {
  if (file.path.endsWith(".gradle") || file.path.endsWith(".gradle.kts")) return [];
  const language = languageOf(file.path);
  if (!language || (language !== "kotlin" && language !== "java")) return [];
  const found: Draft[] = [];
  const text = file.text;

  for (const match of matchesIn(text, /void\s+checkServerTrusted\s*\([^)]*\)\s*\{\s*\}/g)) {
    found.push(
      draft({
        ruleId: "NETWORK-TRUST-ALL",
        title: "Certificate validation accepts every server",
        language,
        path: file.path,
        line: match.line,
        severity: "P0",
        confidence: "confirmed",
        category: "network",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, "checkServerTrusted has an empty body.")],
        attackScenario:
          "A network attacker who can present any certificate can intercept TLS traffic from this client.",
        preconditions: ["This TrustManager is installed on a client the application uses."],
        why: "An empty checkServerTrusted disables certificate chain validation.",
        recommendation: "Delete the custom TrustManager and use the platform trust store. Add pinning only as an additional check.",
        recipe: "manual",
        masvs: ["MASVS-NETWORK"],
        fingerprintSource: "checkServerTrusted-empty",
      }),
    );
  }

  for (const match of matchesIn(text, /boolean\s+verify\s*\([^)]*\)\s*\{\s*return\s+true\s*;\s*\}/g)) {
    found.push(
      draft({
        ruleId: "NETWORK-HOSTNAME-VERIFIER",
        title: "Hostname verification always succeeds",
        language,
        path: file.path,
        line: match.line,
        severity: "P0",
        confidence: "confirmed",
        category: "network",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, "HostnameVerifier.verify returns true.")],
        attackScenario: "Any certificate for any name is treated as valid for the requested host.",
        preconditions: ["This verifier is installed on the application's TLS client."],
        why: "Returning true from verify disables hostname checks.",
        recommendation: "Use the platform hostname verifier. Do not replace it with an allow-all implementation.",
        recipe: "manual",
        masvs: ["MASVS-NETWORK"],
        fingerprintSource: "hostname-verifier-true",
      }),
    );
  }

  for (const match of matchesIn(text, /Cipher\.getInstance\(\s*"(?:[^"]*ECB[^"]*|AES)"/g)) {
    found.push(
      draft({
        ruleId: "CRYPTO-ECB",
        title: "Cipher uses ECB mode",
        language,
        path: file.path,
        line: match.line,
        severity: "P1",
        confidence: "high",
        category: "cryptography",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, /ECB/.test(match.snippet) ? "A cipher transformation uses ECB." : "Cipher.getInstance(\"AES\") uses the platform default, which is ECB.")],
        attackScenario: "Repeated plaintext blocks encrypt to repeated ciphertext, which leaks structure.",
        preconditions: ["The cipher is used on sensitive data."],
        why: "ECB encrypts each block independently.",
        recommendation: "Use an authenticated mode such as AES-GCM with a random nonce generated per message.",
        recipe: "manual",
        masvs: ["MASVS-CRYPTO"],
        fingerprintSource: match.snippet,
      }),
    );
  }

  for (const match of matchesIn(text, /new\s+IvParameterSpec\(\s*(?:new\s+byte\s*\[\s*\]\s*)?\{\s*0(?:\s*,\s*0)+\s*\}|IvParameterSpec\(\s*byteArrayOf\(\s*0(?:\s*,\s*0)+\s*\)/g)) {
    found.push(
      draft({
        ruleId: "CRYPTO-STATIC-IV",
        title: "Initialization vector is a static zero block",
        language,
        path: file.path,
        line: match.line,
        severity: "P1",
        confidence: "high",
        category: "cryptography",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, "An IV is constructed from zero bytes.")],
        attackScenario: "The same plaintext encrypted with the same key produces the same ciphertext.",
        preconditions: ["The IV is reused with a key for sensitive messages."],
        why: "A static IV removes the uniqueness that block modes rely on.",
        recommendation: "Generate a random IV or nonce for every encryption and store it with the ciphertext.",
        recipe: "manual",
        masvs: ["MASVS-CRYPTO"],
        fingerprintSource: "static-iv",
      }),
    );
  }

  for (const match of matchesIn(text, /MessageDigest\.getInstance\(\s*"(MD5|SHA-1|SHA1)"\s*\)/g)) {
    if (!/password/i.test(text)) continue;
    const algorithm = /MD5|SHA-1|SHA1/.exec(match.snippet)?.[0] ?? "MD5";
    found.push(
      draft({
        ruleId: "CRYPTO-WEAK-PASSWORD-HASH",
        title: `Password is hashed with ${algorithm}`,
        language,
        path: file.path,
        line: match.line,
        severity: "P1",
        confidence: "high",
        category: "cryptography",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, `${algorithm} is used in a file that handles a password.`)],
        attackScenario: "Recovered hashes can be reversed with commodity cracking tools much faster than a password hash.",
        preconditions: ["The digest is the stored form of a password."],
        why: "MD5 and SHA-1 are not password hashing functions.",
        recommendation: "Store passwords with a slow adaptive hash such as PBKDF2, scrypt, or argon2, with a unique salt.",
        recipe: "manual",
        masvs: ["MASVS-CRYPTO"],
        fingerprintSource: `${algorithm}-password`,
      }),
    );
  }

  for (const match of matchesIn(text, /MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|set(?:Readable|Writable|Executable)\s*\(\s*true\s*,\s*false\s*\)|openFileOutput\s*\([^,\n]*,\s*[12]\s*\)|getSharedPreferences\s*\([^,\n]*,\s*[12]\s*\)/g)) {
    const sensitive = /password|token|secret|account/i.test(text);
    found.push(
      draft({
        ruleId: "STORAGE-WORLD-ACCESSIBLE",
        title: "File mode grants access to every app",
        language,
        path: file.path,
        line: match.line,
        severity: sensitive ? "P0" : "P1",
        confidence: "confirmed",
        category: "storage",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, "A world-accessible file mode is used.")],
        attackScenario: "Another application on the device can read or write this file.",
        preconditions: ["The process creates the file with this mode."],
        why: "World-accessible modes ignore Android's per-app storage boundary.",
        recommendation: "Create the file with MODE_PRIVATE and share bytes only through a controlled provider or share intent.",
        recipe: "automatic",
        masvs: ["MASVS-STORAGE"],
        fingerprintSource: match.snippet,
      }),
    );
  }

  for (const match of matchesIn(text, /Log\.[dview]\s*\([\s\S]{0,180}?(password|token|secret|authorization|session)/gi)) {
    found.push(
      draft({
        ruleId: "PRIVACY-LOG",
        title: "Sensitive value written to log",
        language,
        path: file.path,
        line: match.line,
        severity: "P2",
        confidence: "high",
        category: "privacy",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, "A log call mentions a credential or session value.")],
        attackScenario: "Log readers, crash reports, and debug builds can collect the value.",
        preconditions: ["The logged expression includes the secret rather than only its field name."],
        why: "Application logs are frequently readable in debug and sometimes in released diagnostics.",
        recommendation: "Remove the secret from the log statement. Log a stable event name instead.",
        recipe: "manual",
        masvs: ["MASVS-PRIVACY"],
        fingerprintSource: redact(match.snippet),
      }),
    );
  }

  for (const match of matchesIn(text, /(?:rawQuery|execSQL)\s*\((?:[^)\n]*\+|[^)\n]*\$)/g)) {
    found.push(
      draft({
        ruleId: "INJECTION-SQL",
        title: "SQL query is built from untrusted text",
        language,
        path: file.path,
        line: match.line,
        severity: "P1",
        confidence: "medium",
        category: "injection",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, "rawQuery or execSQL concatenates or interpolates its SQL.")],
        attackScenario: "If the appended text includes external input, the query can change meaning.",
        preconditions: ["At least one concatenated part is attacker-controlled and no separate whitelist is applied."],
        why: "String-built SQL mixes instructions with data.",
        recommendation: "Use bound parameters (?) and pass values in the selection-args array.",
        recipe: "manual",
        masvs: ["MASVS-CODE"],
        fingerprintSource: redact(match.snippet),
      }),
    );
  }

  for (const match of matchesIn(text, /Runtime\.getRuntime\(\)\.exec\s*\(([^)]*)\)/g)) {
    const argument = match.snippet;
    const fromBridge = /call\.argument|getStringExtra|getQueryParameter|MethodChannel|@ReactMethod/.test(text);
    const literal = /exec\s*\(\s*"/.test(argument);
    if (literal && !fromBridge) continue;
    found.push(
      draft({
        ruleId: "INJECTION-COMMAND",
        title: fromBridge ? "Native boundary passes input to a command" : "Command execution uses a non-literal argument",
        language,
        path: file.path,
        line: match.line,
        severity: fromBridge ? "P1" : "P2",
        confidence: fromBridge ? "high" : "medium",
        category: fromBridge ? "platform" : "injection",
        detectionMethods: ["pattern"],
        evidence: [
          evidence(
            file.path,
            match.line,
            fromBridge
              ? "exec receives a value in a file that also reads a platform channel or intent."
              : "exec is called with a non-literal argument.",
          ),
        ],
        attackScenario: "If the argument includes external input, the caller can choose the command that runs.",
        preconditions: ["The argument is not restricted to a fixed allowlist before exec."],
        why: "Command execution is a trust boundary. Channel and intent data is caller-controlled until checked.",
        recommendation: "Do not pass channel or intent text to exec. Expose a fixed operation and validate every argument.",
        recipe: "manual",
        masvs: ["MASVS-PLATFORM", "MASVS-CODE"],
        fingerprintSource: fromBridge ? "bridge-exec" : redact(match.snippet),
      }),
    );
  }

  if (/addJavascriptInterface\s*\(/.test(text)) {
    const line = lineAt(text, text.search(/addJavascriptInterface\s*\(/));
    const fileAccess = /setAllowFileAccess(?:FromFileURLs)?\s*\(\s*true\s*\)|allowFileAccess\s*=\s*true|setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)/.test(
      text,
    );
    const untrustedUrl = /loadUrl\s*\(\s*(?!["']https?:)/.test(text);
    found.push(
      draft({
        ruleId: "WEBVIEW-JS-BRIDGE",
        title: "WebView exposes a JavaScript interface",
        language,
        path: file.path,
        line,
        severity: fileAccess ? "P1" : "P2",
        confidence: fileAccess || untrustedUrl ? "high" : "medium",
        category: "webview",
        detectionMethods: ["pattern"],
        evidence: [
          evidence(file.path, line, "addJavascriptInterface is called."),
          ...(fileAccess
            ? [evidence(file.path, line, "The same file also enables WebView file access.")]
            : []),
          ...(untrustedUrl
            ? [evidence(file.path, line, "The same file loads a WebView URL that is not a fixed https literal.")]
            : []),
        ],
        attackScenario:
          "Script running in the WebView can call the exposed interface if the loaded document is not fully trusted.",
        preconditions: [
          "JavaScript is enabled or the platform version exposes the interface without it.",
          "The WebView can load content the application does not fully control.",
        ],
        why: "A JavaScript interface crosses from web content into application code.",
        recommendation:
          "Remove the interface if a WebView message channel is enough. Otherwise load only trusted https content, disable file access, and check the origin before handling messages.",
        recipe: "manual",
        masvs: ["MASVS-PLATFORM"],
        fingerprintSource: `js-bridge:${fileAccess}:${untrustedUrl}`,
      }),
    );
  }

  for (const match of matchesIn(text, /setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)|setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)/g)) {
    found.push(
      draft({
        ruleId: "WEBVIEW-FILE-ACCESS",
        title: "WebView file URL access is enabled",
        language,
        path: file.path,
        line: match.line,
        severity: "P1",
        confidence: "high",
        category: "webview",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, "Universal or file-URL access is turned on.")],
        attackScenario: "A document loaded from a file URL may read other files the WebView can access.",
        preconditions: ["The WebView can open a file URL or untrusted content."],
        why: "These settings relax the WebView's file boundary.",
        recommendation: "Leave universal file access disabled. Load remote content over https.",
        recipe: "manual",
        masvs: ["MASVS-PLATFORM"],
        fingerprintSource: match.snippet,
      }),
    );
  }

  for (const match of matchesIn(text, /\.loadUrl\s*\(\s*(?!["']https:)([^)\n]+)\)/g)) {
    const argument = match.snippet;
    if (/"https:|'https:/.test(argument) || /javascript:/.test(argument)) continue;
    found.push(
      draft({
        ruleId: "WEBVIEW-UNTRUSTED-URL",
        title: "WebView loads a URL that is not a fixed https address",
        language,
        path: file.path,
        line: match.line,
        severity: /http:\/\//.test(argument) ? "P2" : "P2",
        confidence: "medium",
        category: "webview",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, "loadUrl is called without a fixed https literal.")],
        attackScenario: "If the URL includes external input, the WebView opens a page the caller chooses.",
        preconditions: ["The URL is influenced by an intent, deep link, or other untrusted source."],
        why: "Navigation targets should be restricted before a WebView loads them.",
        recommendation: "Allow only expected https hosts. Reject file, javascript, and intent schemes.",
        recipe: "manual",
        masvs: ["MASVS-PLATFORM"],
        fingerprintSource: "load-url",
      }),
    );
  }

  const redirect = /getParcelableExtra[\s\S]{0,400}startActivity\s*\(/.exec(text);
  if (redirect?.index !== undefined) {
    const line = lineAt(text, redirect.index);
    found.push(
      draft({
        ruleId: "PLATFORM-INTENT-REDIRECT",
        title: "Intent extra is started as an activity",
        language,
        path: file.path,
        line,
        severity: "P1",
        confidence: "medium",
        category: "platform",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, line, "A parcelable extra is followed by startActivity nearby.")],
        attackScenario: "If the extra is an Intent from another app, this component can open a target the caller chooses.",
        preconditions: ["The component is reachable by an untrusted caller and the extra is not validated."],
        why: "Forwarding a nested intent moves the caller's choice into this app's privileges.",
        recommendation: "Ignore nested intents. Start an explicit in-app destination chosen by this application.",
        recipe: "manual",
        masvs: ["MASVS-PLATFORM"],
        fingerprintSource: "intent-redirect",
      }),
    );
  }

  for (const match of matchesIn(text, /PendingIntent\.get(?:Activity|Service|Broadcast)\s*\(([\s\S]{0,350}?)\)/g)) {
    const body = match.snippet + (text.slice(match.index, match.index + 350));
    if (/FLAG_IMMUTABLE/.test(body)) continue;
    found.push(
      draft({
        ruleId: "PLATFORM-MUTABLE-PENDING-INTENT",
        title: "PendingIntent is created without FLAG_IMMUTABLE",
        language,
        path: file.path,
        line: match.line,
        severity: "P2",
        confidence: "medium",
        category: "platform",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, "A PendingIntent factory call does not include FLAG_IMMUTABLE.")],
        attackScenario: "A mutable pending intent can be altered by another app that receives it.",
        preconditions: ["The pending intent is handed to code outside the application and mutability is not required."],
        why: "Immutable pending intents prevent other apps from filling in unspecified fields.",
        recommendation: "Add FLAG_IMMUTABLE unless this intent must be mutated by a trusted framework API.",
        recipe: "automatic",
        masvs: ["MASVS-PLATFORM"],
        fingerprintSource: "pending-intent",
      }),
    );
  }

  for (const match of matchesIn(text, /SSLContext\.getInstance\(\s*"(?:SSL|SSLv3|TLSv1|TLSv1\.1)"\s*\)|setEnabledProtocols\s*\([\s\S]{0,160}?(?:SSLv3|SSL|TLSv1\.1|TLSv1)(?![.\w])/g)) {
    found.push(
      draft({
        ruleId: "NETWORK-WEAK-TLS",
        title: "TLS client requests an obsolete protocol",
        language,
        path: file.path,
        line: match.line,
        severity: "P1",
        confidence: "high",
        category: "network",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, "SSLContext.getInstance requests SSL or TLS 1.0/1.1.")],
        attackScenario: "Connections made with this context can use a protocol that current clients no longer accept.",
        preconditions: ["This context is used for the application's network connections."],
        why: "SSL, SSLv3, TLS 1.0, and TLS 1.1 are obsolete.",
        recommendation: "Use the platform default TLS context, which negotiates TLS 1.2 or newer.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: match.snippet,
      }),
    );
  }

  for (const match of matchesIn(text, /Intent\.parseUri\s*\([^)]*URI_(?:ALLOW_UNSAFE|INTENT_SCHEME)/g)) {
    found.push(
      draft({
        ruleId: "PLATFORM-PARSE-URI",
        title: "Intent.parseUri allows an unsafe intent URI",
        language,
        path: file.path,
        line: match.line,
        severity: "P1",
        confidence: "high",
        category: "platform",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, "Intent.parseUri is called with URI_ALLOW_UNSAFE or URI_INTENT_SCHEME.")],
        attackScenario: "A crafted intent URI can select a component or extra inside this application's privileges.",
        preconditions: ["The URI text comes from outside the application."],
        why: "Those flags restore intent fields that Android otherwise strips from a URI.",
        recommendation: "Parse only the data you expect. Do not pass URI_ALLOW_UNSAFE or URI_INTENT_SCHEME on untrusted text.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: "parse-uri",
      }),
    );
  }

  for (const match of matchesIn(text, /(?:DexClassLoader|InMemoryDexClassLoader|PathClassLoader|BaseDexClassLoader)\s*\(/g)) {
    found.push(
      draft({
        ruleId: "CODE-DYNAMIC-LOAD",
        title: "A dex class loader loads bytecode at runtime",
        language,
        path: file.path,
        line: match.line,
        severity: "P1",
        confidence: "high",
        category: "injection",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, "A dex class loader is constructed.")],
        attackScenario: "Code loaded from a path outside the signed APK runs with this application's identity.",
        preconditions: ["The dex path can point at bytes the application did not ship."],
        why: "Dynamic dex loading moves execution outside the code reviewed in the APK.",
        recommendation: "Ship the code inside the application. Do not load dex from storage or from a downloaded file.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: "dex-class-loader",
      }),
    );
  }

  for (const match of matchesIn(text, /setSafeBrowsingEnabled\s*\(\s*false\s*\)/g)) {
    found.push(
      draft({
        ruleId: "WEBVIEW-SAFE-BROWSING",
        title: "WebView safe browsing is disabled",
        language,
        path: file.path,
        line: match.line,
        severity: "P2",
        confidence: "high",
        category: "webview",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, "setSafeBrowsingEnabled(false) is called.")],
        attackScenario: "The WebView will not use the platform check that blocks known harmful sites.",
        preconditions: ["This WebView loads pages that are not a fixed allowlist."],
        why: "Safe browsing is a platform control for web content. Turning it off removes that check.",
        recommendation: "Leave safe browsing enabled. Restrict the WebView to expected https hosts.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: "safe-browsing-off",
      }),
    );
  }

  for (const match of matchesIn(text, /CONTEXT_IGNORE_SECURITY|CONTEXT_INCLUDE_CODE/g)) {
    found.push(
      draft({
        ruleId: "CODE-PACKAGE-CONTEXT",
        title: "Package context skips a signature check or loads another app's code",
        language,
        path: file.path,
        line: match.line,
        severity: "P1",
        confidence: "high",
        category: "injection",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, "CONTEXT_IGNORE_SECURITY or CONTEXT_INCLUDE_CODE is used.")],
        attackScenario: "Code from another package can run with this application's identity, or a signature mismatch is ignored.",
        preconditions: ["The package name can refer to an app this process did not ship."],
        why: "CONTEXT_IGNORE_SECURITY skips the signature check. CONTEXT_INCLUDE_CODE loads that package's code into this process.",
        recommendation: "Create a context only for this application. Do not pass CONTEXT_IGNORE_SECURITY or CONTEXT_INCLUDE_CODE.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: `package-context:${match.index}`,
      }),
    );
  }

  for (const match of matchesIn(text, /System\.load\s*\(/g)) {
    found.push(
      draft({
        ruleId: "CODE-NATIVE-LOAD",
        title: "Native code is loaded from a filesystem path",
        language,
        path: file.path,
        line: match.line,
        severity: "P1",
        confidence: "high",
        category: "injection",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, "System.load is called with a path.")],
        attackScenario: "A native library outside the signed APK runs with this application's identity.",
        preconditions: ["The path can point at a file the application did not ship."],
        why: "System.load takes a filesystem path. System.loadLibrary loads a library packaged in the APK.",
        recommendation: "Load native code with System.loadLibrary from libraries packaged in the APK.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: "system-load",
      }),
    );
  }

  for (const match of matchesIn(text, /\.setSeed\s*\(\s*(?:\d+|["'])/g)) {
    const window = text.slice(Math.max(0, match.index - 220), match.index + 40);
    if (!/SecureRandom/.test(window)) continue;
    found.push(
      draft({
        ruleId: "CRYPTO-STATIC-SEED",
        title: "SecureRandom is seeded from a fixed value",
        language,
        path: file.path,
        line: match.line,
        severity: "P1",
        confidence: "high",
        category: "cryptography",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, "SecureRandom.setSeed is called with a literal.")],
        attackScenario: "Random values drawn after a fixed seed can be repeated by anyone who knows the seed.",
        preconditions: ["The seeded generator supplies keys, nonces, or tokens."],
        why: "A fixed seed replaces the platform entropy SecureRandom starts with.",
        recommendation: "Use SecureRandom without setSeed. Let the platform seed it.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: "secure-random-seed",
      }),
    );
  }

  for (const match of matchesIn(text, /HttpLoggingInterceptor\.Level\.BODY/g)) {
    const before = text.slice(Math.max(0, match.index - 180), match.index);
    if (/BuildConfig\.DEBUG/.test(before)) continue;
    found.push(
      draft({
        ruleId: "PRIVACY-HTTP-BODY",
        title: "HTTP logger records full bodies",
        language,
        path: file.path,
        line: match.line,
        severity: "P2",
        confidence: "high",
        category: "privacy",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, "HttpLoggingInterceptor is set to BODY.")],
        attackScenario: "Request and response bodies, including credentials sent on those calls, are written to the log.",
        preconditions: ["The interceptor is installed on a client that sends sensitive requests."],
        why: "BODY logging stores the full HTTP message, not just the URL.",
        recommendation: "Do not log bodies in release. Limit logging to NONE, or to a debug build that does not send real secrets.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: "http-body-log",
      }),
    );
  }

  found.push(...scanSecrets(file, language));
  found.push(...scanPlatformStandards(file, language));
  return found;
}

function around(text: string, index: number, span = 350): string {
  return text.slice(Math.max(0, index - 80), Math.min(text.length, index + span));
}

function scanPlatformStandards(file: SourceFile, language: Language): Draft[] {
  const text = file.text;
  const found: Draft[] = [];

  for (const match of matchesIn(text, /fun\s+checkServerTrusted\s*\([^)]*\)\s*\{\s*\}/g)) {
    found.push(
      draft({
        ruleId: "NETWORK-TRUST-ALL",
        title: "Certificate validation accepts every server",
        language,
        path: file.path,
        line: match.line,
        severity: "P0",
        confidence: "confirmed",
        category: "network",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, "checkServerTrusted has an empty Kotlin body.")],
        attackScenario: "A network attacker who can present any certificate can intercept TLS traffic from this client.",
        preconditions: ["This TrustManager is installed on a client the application uses."],
        why: "An empty checkServerTrusted disables certificate chain validation.",
        recommendation: "Delete the custom TrustManager and use the platform trust store.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: "kotlin-checkServerTrusted-empty",
      }),
    );
  }

  for (const match of matchesIn(text, /HostnameVerifier\s*\{\s*_\s*,\s*_\s*->\s*true\s*\}/g)) {
    found.push(
      draft({
        ruleId: "NETWORK-HOSTNAME-VERIFIER",
        title: "Hostname verification always succeeds",
        language,
        path: file.path,
        line: match.line,
        severity: "P0",
        confidence: "confirmed",
        category: "network",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, "A Kotlin HostnameVerifier returns true.")],
        attackScenario: "Any certificate for any name is treated as valid for the requested host.",
        preconditions: ["This verifier is installed on the application's TLS client."],
        why: "Returning true from the verifier disables hostname checks.",
        recommendation: "Use the platform hostname verifier.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: "kotlin-hostname-verifier-true",
      }),
    );
  }

  const sslError = /onReceivedSslError[\s\S]{0,400}?handler\.proceed\s*\(/.exec(text);
  if (sslError?.index !== undefined) {
    const line = lineAt(text, sslError.index);
    found.push(
      draft({
        ruleId: "NETWORK-SSL-ERROR-PROCEED",
        title: "WebView continues after a TLS error",
        language,
        path: file.path,
        line,
        severity: "P0",
        confidence: "confirmed",
        category: "network",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, line, "onReceivedSslError calls handler.proceed().")],
        attackScenario: "The WebView continues loading when certificate validation has already failed.",
        preconditions: ["This callback is installed on a WebView that loads remote content."],
        why: "proceed() accepts the failed TLS connection.",
        recommendation: "Call handler.cancel() and close or report the error. Do not continue the load.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: "ssl-error-proceed",
      }),
    );
  }

  for (const match of matchesIn(text, /MIXED_CONTENT_ALWAYS_ALLOW/g)) {
    found.push(
      draft({
        ruleId: "NETWORK-MIXED-CONTENT",
        title: "WebView always allows mixed content",
        language,
        path: file.path,
        line: match.line,
        severity: "P2",
        confidence: "high",
        category: "webview",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, "MIXED_CONTENT_ALWAYS_ALLOW is set.")],
        attackScenario: "An https page in this WebView can load http subresources.",
        preconditions: ["The WebView loads a page that requests insecure subresources."],
        why: "Always-allow mixed content removes the browser restriction on active mixed content.",
        recommendation: "Use MIXED_CONTENT_NEVER_ALLOW unless a specific legacy page has been reviewed.",
        recipe: "automatic",
        masvs: [],
        fingerprintSource: "mixed-content",
      }),
    );
  }

  for (const match of matchesIn(text, /Cipher\.getInstance\(\s*"(?:DESede|DES|RC2|RC4|Blowfish|PBEWithMD5)[^"]*"/g)) {
    found.push(
      draft({
        ruleId: "CRYPTO-WEAK-ALGORITHM",
        title: "Cipher uses an obsolete algorithm",
        language,
        path: file.path,
        line: match.line,
        severity: "P1",
        confidence: "high",
        category: "cryptography",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, "Cipher.getInstance requests an obsolete algorithm.")],
        attackScenario: "Data protected by this cipher can be recovered with practical attacks against the algorithm.",
        preconditions: ["The cipher protects sensitive data."],
        why: "DES, RC4, Blowfish, and MD5-based password ciphers are not current practice.",
        recommendation: "Use AES-GCM with a random nonce, or a current password-based key derivation function for passwords.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: match.snippet,
      }),
    );
  }

  for (const match of matchesIn(text, /SecretKeySpec\(\s*"[^"]{8,}"\.(?:toByteArray|getBytes)\s*\(/g)) {
    found.push(
      draft({
        ruleId: "CRYPTO-HARDCODED-KEY",
        title: "Cipher key is a string literal",
        language,
        path: file.path,
        line: match.line,
        severity: "P1",
        confidence: "confirmed",
        category: "cryptography",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, "SecretKeySpec is built from a string literal.")],
        attackScenario: "Anyone with the application or its source can use the same key.",
        preconditions: ["The literal is the key used for sensitive data."],
        why: "A key in source is shared by every install and cannot be rotated quietly.",
        recommendation: "Generate or unwrap the key in the Android Keystore. Do not embed it in source.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: "hardcoded-key",
      }),
    );
  }

  const insecureRandom = /(?:new\s+java\.util\.Random\s*\(|java\.util\.Random\s*\(|new\s+Random\s*\()/.exec(text);
  if (insecureRandom?.index !== undefined && /nextBytes|IvParameterSpec|SecretKeySpec/.test(around(text, insecureRandom.index))) {
    const line = lineAt(text, insecureRandom.index);
    found.push(
      draft({
        ruleId: "CRYPTO-INSECURE-RANDOM",
        title: "java.util.Random supplies cryptographic material",
        language,
        path: file.path,
        line,
        severity: "P2",
        confidence: "high",
        category: "cryptography",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, line, "java.util.Random is near key or IV generation.")],
        attackScenario: "Output of java.util.Random can be predicted, so keys or IVs derived from it can be reconstructed.",
        preconditions: ["The random bytes are used as a key, nonce, or IV."],
        why: "java.util.Random is not a cryptographic generator.",
        recommendation: "Use java.security.SecureRandom for keys, nonces, and IVs.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: "insecure-random",
      }),
    );
  }

  if (/getSharedPreferences|SharedPreferences/.test(text)) {
    const prefs = /putString\(\s*["'][^"']*(?:token|password|secret|session|auth)[^"']*["']/.exec(text);
    if (prefs?.index !== undefined) {
      const line = lineAt(text, prefs.index);
      found.push(
        draft({
          ruleId: "STORAGE-PREFS-SECRET",
          title: "Secret-like value stored in shared preferences",
          language,
          path: file.path,
          line,
          severity: "P2",
          confidence: "medium",
          category: "storage",
          detectionMethods: ["pattern"],
          evidence: [evidence(file.path, line, "putString uses a credential-like key.")],
          attackScenario: "Preferences are stored in plaintext and can be read from a backup or a compromised device.",
          preconditions: ["The stored value is a credential or session token."],
          why: "Shared preferences are not an encrypted secret store.",
          recommendation: "Store credentials in the Android Keystore or an encrypted preferences implementation.",
          recipe: "manual",
          masvs: [],
          fingerprintSource: "android-prefs-secret",
        }),
      );
    }
  }

  const external = /getExternalStorageDirectory|getExternalStoragePublicDirectory/.exec(text);
  if (external?.index !== undefined && /password|token|secret/i.test(around(text, external.index, 500))) {
    const line = lineAt(text, external.index);
    found.push(
      draft({
        ruleId: "STORAGE-EXTERNAL",
        title: "Sensitive value is written toward external storage",
        language,
        path: file.path,
        line,
        severity: "P1",
        confidence: "high",
        category: "storage",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, line, "External storage is used in the same region as a credential-like value.")],
        attackScenario: "Other apps or a backup can read files placed on external storage.",
        preconditions: ["The sensitive value is actually written to the external location."],
        why: "External storage is a shared area, not the app's private directory.",
        recommendation: "Keep secrets in app-private storage or the Android Keystore.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: "external-storage",
      }),
    );
  }

  const clipboard = /setPrimaryClip|ClipData\.newPlainText/.exec(text);
  if (clipboard?.index !== undefined && /password|token|secret/i.test(around(text, clipboard.index, 300))) {
    const line = lineAt(text, clipboard.index);
    found.push(
      draft({
        ruleId: "PRIVACY-CLIPBOARD",
        title: "Sensitive value copied to the clipboard",
        language,
        path: file.path,
        line,
        severity: "P2",
        confidence: "medium",
        category: "privacy",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, line, "Clipboard text is built next to a credential-like value.")],
        attackScenario: "Other apps that can read the clipboard can collect the copied value.",
        preconditions: ["The clipboard payload includes the secret rather than a public label."],
        why: "Clipboard contents are shared outside the application.",
        recommendation: "Do not place credentials or session tokens on the clipboard.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: "clipboard",
      }),
    );
  }

  const debug = /setWebContentsDebuggingEnabled\s*\(\s*true\s*\)/.exec(text);
  if (debug?.index !== undefined && !/BuildConfig\.DEBUG/.test(text.slice(Math.max(0, debug.index - 160), debug.index))) {
    const line = lineAt(text, debug.index);
    found.push(
      draft({
        ruleId: "WEBVIEW-DEBUG",
        title: "WebView debugging is enabled",
        language,
        path: file.path,
        line,
        severity: "P2",
        confidence: "high",
        category: "webview",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, line, "setWebContentsDebuggingEnabled(true) is not inside a nearby debug guard.")],
        attackScenario: "A debugger attached to the device can inspect the WebView.",
        preconditions: ["This call remains in the release build."],
        why: "WebView debugging exposes page content and script state.",
        recommendation: "Call setWebContentsDebuggingEnabled only inside a debug build check, and pass false for release.",
        recipe: "automatic",
        masvs: [],
        fingerprintSource: "webview-debug",
      }),
    );
  }

  for (const match of matchesIn(text, /\.loadUrl\s*\(\s*["']javascript:/g)) {
    found.push(
      draft({
        ruleId: "WEBVIEW-JS-URL",
        title: "WebView loads a javascript URL",
        language,
        path: file.path,
        line: match.line,
        severity: "P1",
        confidence: "high",
        category: "webview",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, "loadUrl is called with a javascript: URL.")],
        attackScenario: "The WebView executes script supplied to loadUrl in the page origin.",
        preconditions: ["Any part of the javascript: URL includes untrusted data."],
        why: "javascript: URLs mix navigation with script execution.",
        recommendation: "Use evaluateJavascript with a fixed script, or a message channel. Do not build a javascript: URL from external input.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: "javascript-url",
      }),
    );
  }

  if (/ZipEntry/.test(text) && /(?:entry\.name|getName\(\))/.test(text) && /File\s*\(/.test(text) && !/canonicalPath/.test(text)) {
    const index = text.search(/ZipEntry|getName\(\)|entry\.name/);
    const line = lineAt(text, Math.max(0, index));
    found.push(
      draft({
        ruleId: "INJECTION-ZIP-SLIP",
        title: "Zip entry name is used as a filesystem path",
        language,
        path: file.path,
        line,
        severity: "P1",
        confidence: "medium",
        category: "injection",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, line, "A zip entry name is passed to a file path and no canonicalPath check was found.")],
        attackScenario: "A zip entry whose name contains parent-directory segments can write outside the destination directory.",
        preconditions: ["The archive comes from an untrusted source and the entry name is used without normalization."],
        why: "Zip entry names are data. Using them directly as paths trusts the archive author.",
        recommendation: "Resolve the output file and require its canonical path to stay inside the destination directory.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: "zip-slip",
      }),
    );
  }

  const pathExtra = /File\s*\([^)\n]*getStringExtra/.exec(text);
  if (pathExtra?.index !== undefined) {
    const line = lineAt(text, pathExtra.index);
    found.push(
      draft({
        ruleId: "INJECTION-PATH",
        title: "Intent extra is used as a file path",
        language,
        path: file.path,
        line,
        severity: "P2",
        confidence: "medium",
        category: "injection",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, line, "A File constructor receives getStringExtra.")],
        attackScenario: "If the extra contains directory traversal, the file operation can leave the intended directory.",
        preconditions: ["The component accepts the extra from an untrusted caller and does not constrain the path."],
        why: "External path text is not a safe relative path.",
        recommendation: "Accept an identifier, map it to a known file, and reject values that contain separators or parent segments.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: "intent-path",
      }),
    );
  }

  if (/ObjectInputStream/.test(text) && /readObject\s*\(/.test(text)) {
    const index = text.search(/readObject\s*\(/);
    const line = lineAt(text, Math.max(0, index));
    found.push(
      draft({
        ruleId: "CODE-DESERIALIZATION",
        title: "ObjectInputStream deserializes a stream",
        language,
        path: file.path,
        line,
        severity: "P1",
        confidence: "medium",
        category: "injection",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, line, "readObject is used with ObjectInputStream in this file.")],
        attackScenario: "If the stream includes untrusted bytes, deserialization can instantiate unexpected types.",
        preconditions: ["The stream is not limited to types this application produced and still trusts."],
        why: "Java object deserialization executes type logic from the stream.",
        recommendation: "Read a versioned data format. Do not deserialize object graphs from other apps or the network.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: "read-object",
      }),
    );
  }

  return found;
}

function scanDart(file: SourceFile): Draft[] {
  if (!file.path.endsWith(".dart")) return [];
  const found: Draft[] = [];
  const badCert = /badCertificateCallback[\s\S]{0,180}?=>\s*true|onBadCertificate[\s\S]{0,180}?=>\s*true/.exec(file.text);
  if (badCert?.index !== undefined) {
    const line = lineAt(file.text, badCert.index);
    found.push(
      draft({
        ruleId: "FLUTTER-BAD-CERTIFICATE",
        title: "Dart HTTP client accepts any certificate",
        language: "dart",
        path: file.path,
        line,
        severity: "P0",
        confidence: "confirmed",
        category: "network",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, line, "A certificate callback returns true.")],
        attackScenario: "Any certificate is treated as valid, so a network attacker can impersonate the server.",
        preconditions: ["This callback is installed on a client that talks to a real service."],
        why: "Returning true skips certificate checks.",
        recommendation: "Remove the callback and use default TLS validation.",
        recipe: "manual",
        masvs: ["MASVS-NETWORK"],
        fingerprintSource: "bad-certificate",
      }),
    );
  }
  const prefs = /setString\(\s*['"][^'"]*(token|password|secret|session)[^'"]*['"]/.exec(file.text);
  if (prefs?.index !== undefined && /SharedPreferences/.test(file.text)) {
    const line = lineAt(file.text, prefs.index);
    found.push(
      draft({
        ruleId: "STORAGE-PREFS-SECRET",
        title: "Secret-like value stored in shared preferences",
        language: "dart",
        path: file.path,
        line,
        severity: "P2",
        confidence: "medium",
        category: "storage",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, line, "SharedPreferences.setString uses a credential-like key.")],
        attackScenario: "On a rooted device or through a backup, preferences are readable as plaintext.",
        preconditions: ["The stored value is a credential or session token."],
        why: "Shared preferences are not an encrypted secret store.",
        recommendation: "Keep session secrets in an encrypted store such as encrypted shared preferences or the platform keystore.",
        recipe: "manual",
        masvs: ["MASVS-STORAGE"],
        fingerprintSource: "prefs-secret",
      }),
    );
  }
  return found;
}

function scanScript(file: SourceFile): Draft[] {
  if (!/\.(tsx|ts|jsx|js)$/.test(file.path)) return [];
  const language: Language = file.path.endsWith(".ts") || file.path.endsWith(".tsx") ? "typescript" : "javascript";
  const found: Draft[] = [];
  const storage = /AsyncStorage\.setItem\(\s*['"][^'"]*(token|password|secret|session|auth)[^'"]*['"]/.exec(file.text);
  if (storage?.index !== undefined) {
    const line = lineAt(file.text, storage.index);
    found.push(
      draft({
        ruleId: "STORAGE-ASYNC-SECRET",
        title: "Secret-like value stored in AsyncStorage",
        language,
        path: file.path,
        line,
        severity: "P2",
        confidence: "high",
        category: "storage",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, line, "AsyncStorage.setItem uses a credential-like key.")],
        attackScenario: "AsyncStorage contents are plaintext and can be read from a backup or a compromised device.",
        preconditions: ["The stored value is a credential or session token."],
        why: "AsyncStorage is an unencrypted key-value store.",
        recommendation: "Store tokens in the platform keystore through a reviewed secure-storage module.",
        recipe: "manual",
        masvs: ["MASVS-STORAGE"],
        fingerprintSource: "async-storage",
      }),
    );
  }
  const wildcard = /originWhitelist\s*=\s*\{\s*\[\s*['"]\*['"]/.exec(file.text);
  if (wildcard?.index !== undefined) {
    const line = lineAt(file.text, wildcard.index);
    found.push(
      draft({
        ruleId: "WEBVIEW-ORIGIN-WILDCARD",
        title: "WebView origin allowlist is a wildcard",
        language,
        path: file.path,
        line,
        severity: "P2",
        confidence: "medium",
        category: "webview",
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, line, "originWhitelist includes *.")],
        attackScenario: "The WebView will treat origins the application did not name as allowed.",
        preconditions: ["The WebView loads content beyond a single trusted site."],
        why: "A wildcard removes the origin restriction.",
        recommendation: "List the specific https origins the screen is intended to load.",
        recipe: "manual",
        masvs: ["MASVS-PLATFORM"],
        fingerprintSource: "origin-wildcard",
      }),
    );
  }
  found.push(...scanSecrets(file, language));
  return found;
}

function scanGradle(file: SourceFile): Draft[] {
  if (!file.path.endsWith(".gradle") && !file.path.endsWith(".gradle.kts")) return [];
  const found: Draft[] = [];
  const release = releaseBlock(file.text);
  if (/(?:isDebuggable\s*=\s*true|debuggable\s*(?:=)?\s*true)/.test(release)) {
    const line = lineAt(file.text, file.text.indexOf(release) + release.search(/[Dd]ebuggable/));
    found.push(
      draft({
        ruleId: "BUILD-RELEASE-DEBUGGABLE",
        title: "Release build type is debuggable",
        language: "gradle",
        path: file.path,
        line,
        severity: "P1",
        confidence: "confirmed",
        category: "build",
        detectionMethods: ["config"],
        evidence: [evidence(file.path, line, "The release build type sets debuggable to true.")],
        attackScenario: "A release artifact can be attached to a debugger and inspected at runtime.",
        preconditions: ["This build type is the one used for the shipped artifact."],
        why: "Debuggable release builds disable protections that depend on a non-debug runtime.",
        recommendation: "Set the release build type's debuggable flag to false. Keep debugging on the debug build type.",
        recipe: "automatic",
        masvs: ["MASVS-RESILIENCE"],
        fingerprintSource: "release-debuggable",
      }),
    );
  }
  for (const match of matchesIn(file.text, /(?:storePassword|keyPassword)\s*(?:=|:)\s*["'][^"']+["']/g)) {
    found.push(
      draft({
        ruleId: "BUILD-SIGNING-SECRET",
        title: "Signing secret written in Gradle",
        language: "gradle",
        path: file.path,
        line: match.line,
        severity: "P1",
        confidence: "high",
        category: "build",
        detectionMethods: ["config"],
        evidence: [evidence(file.path, match.line, "A signing password is assigned from a literal.")],
        attackScenario: "Anyone with the repository can attempt to use the signing material.",
        preconditions: ["The literal is the real signing password."],
        why: "Signing secrets in Gradle are copied to every clone of the project.",
        recommendation: "Remove the literal, rotate the credential, and supply it from the environment or a local untracked file.",
        recipe: "manual",
        masvs: ["MASVS-STORAGE"],
        fingerprintSource: match.snippet.includes("storePassword") ? "storePassword" : "keyPassword",
      }),
    );
  }
  found.push(...dependencyFindings(file));
  return found;
}

function scanXmlConfig(file: SourceFile): Draft[] {
  if (!file.path.endsWith(".xml") || file.path.endsWith("AndroidManifest.xml")) return [];
  const found: Draft[] = [];
  if (/<certificates\b[^>]*src="user"/.test(file.text) && !/debug-overrides/.test(file.text)) {
    const line = lineAt(file.text, file.text.search(/src="user"/));
    found.push(
      draft({
        ruleId: "NETWORK-USER-CA",
        title: "User-installed certificate authorities are trusted",
        language: "xml",
        path: file.path,
        line,
        severity: "P2",
        confidence: "medium",
        category: "network",
        detectionMethods: ["config"],
        evidence: [evidence(file.path, line, "A trust anchor uses src=user outside debug-overrides.")],
        attackScenario: "A user or management profile can install a certificate that this app will trust.",
        preconditions: ["This network security config is used by the release application."],
        why: "Trusting user CAs in the base config extends trust beyond the platform store.",
        recommendation: "Limit user CAs to debug-overrides. Keep the release base config on the system trust store.",
        recipe: "manual",
        masvs: ["MASVS-NETWORK"],
        fingerprintSource: "user-ca",
      }),
    );
  }
  if (/<root-path\b|path\s*=\s*"\/"/.test(file.text) && /<paths\b/.test(file.text)) {
    const line = lineAt(file.text, file.text.search(/<root-path\b|path\s*=\s*"\/"/));
    found.push(
      draft({
        ruleId: "STORAGE-PROVIDER-PATH",
        title: "FileProvider exposes a broad filesystem path",
        language: "xml",
        path: file.path,
        line,
        severity: "P1",
        confidence: "high",
        category: "storage",
        detectionMethods: ["config"],
        evidence: [evidence(file.path, line, "A provider path is root-path or an unrestricted path.")],
        attackScenario: "A granted content URI can address files outside the directory the provider was meant to share.",
        preconditions: ["A component grants this provider's URIs to another app."],
        why: "root-path and a root path attribute remove the directory limit.",
        recommendation: "Share one app-specific directory. Remove root-path and do not set path to the filesystem root.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: "provider-root",
      }),
    );
  }
  if (/cleartextTrafficPermitted\s*=\s*"true"/.test(file.text)) {
    const line = lineAt(file.text, file.text.search(/cleartextTrafficPermitted/));
    found.push(
      draft({
        ruleId: "NETWORK-CLEARTEXT",
        title: "Cleartext traffic is permitted",
        language: "xml",
        path: file.path,
        line,
        severity: "P2",
        confidence: "high",
        category: "network",
        detectionMethods: ["config"],
        evidence: [evidence(file.path, line, "cleartextTrafficPermitted is true.")],
        attackScenario: "Network traffic that uses this config can be read and modified on the path.",
        preconditions: ["A release endpoint still uses http under this config."],
        why: "Cleartext has no confidentiality or integrity.",
        recommendation: "Permit cleartext only for a named development domain, or turn it off and use https.",
        recipe: "automatic",
        masvs: ["MASVS-NETWORK"],
        fingerprintSource: `cleartext:${file.path}`,
      }),
    );
  }
  return found;
}

function scanManifestPolicy(file: SourceFile): Draft[] {
  const found: Draft[] = [];
  if (/android:sharedUserId\s*=\s*"/.test(file.text)) {
    const line = lineAt(file.text, file.text.search(/android:sharedUserId/));
    found.push(
      draft({
        ruleId: "PLATFORM-SHARED-USER-ID",
        title: "Application sets a shared user id",
        language: "xml",
        path: file.path,
        line,
        severity: "P2",
        confidence: "high",
        category: "platform",
        detectionMethods: ["config"],
        evidence: [evidence(file.path, line, "android:sharedUserId is set.")],
        attackScenario: "Every app signed into this shared user can read this app's private data.",
        preconditions: ["Another package is installed with the same shared user id and a compatible signature."],
        why: "sharedUserId merges private storage across packages. The attribute is obsolete.",
        recommendation: "Remove sharedUserId. Share data through an explicit, permissioned provider.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: "shared-user-id",
      }),
    );
  }
  if (/android:allowTaskReparenting\s*=\s*"true"/.test(file.text)) {
    const line = lineAt(file.text, file.text.search(/android:allowTaskReparenting/));
    found.push(
      draft({
        ruleId: "PLATFORM-TASK-REPARENT",
        title: "Activity allows another task to reparent it",
        language: "xml",
        path: file.path,
        line,
        severity: "P2",
        confidence: "high",
        category: "platform",
        detectionMethods: ["config"],
        evidence: [evidence(file.path, line, "android:allowTaskReparenting is true.")],
        attackScenario: "Another task can move this activity into its own task while the activity stays enabled.",
        preconditions: ["The activity can be started by an app other than this one."],
        why: "allowTaskReparenting lets a different task take this activity.",
        recommendation: "Leave allowTaskReparenting at its default false.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: "task-reparent",
      }),
    );
  }
  if (/android:requestLegacyExternalStorage\s*=\s*"true"/.test(file.text)) {
    const line = lineAt(file.text, file.text.search(/requestLegacyExternalStorage/));
    found.push(
      draft({
        ruleId: "STORAGE-LEGACY-EXTERNAL",
        title: "Legacy external storage is requested",
        language: "xml",
        path: file.path,
        line,
        severity: "P3",
        confidence: "medium",
        category: "storage",
        detectionMethods: ["config"],
        evidence: [evidence(file.path, line, "requestLegacyExternalStorage is true.")],
        attackScenario: "The app receives the broad external-storage view used before scoped storage.",
        preconditions: ["The app still reads or writes shared storage under this flag."],
        why: "The flag restores a wider storage model than current Android defaults.",
        recommendation: "Remove the flag and use scoped storage or the system document picker.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: "legacy-external",
      }),
    );
  }
  for (const match of file.text.matchAll(/<permission\b([^>]*?)\/?>/g)) {
    const tag = match[1] ?? "";
    const level = /android:protectionLevel\s*=\s*"([^"]*)"/.exec(tag)?.[1];
    if (level && level !== "normal") continue;
    const name = /android:name\s*=\s*"([^"]*)"/.exec(tag)?.[1] ?? "unnamed";
    const line = lineAt(file.text, match.index ?? 0);
    found.push(
      draft({
        ruleId: "PLATFORM-NORMAL-PERMISSION",
        title: `Custom permission ${name} does not require a signature`,
        language: "xml",
        path: file.path,
        line,
        severity: "P2",
        confidence: level === "normal" ? "high" : "medium",
        category: "platform",
        detectionMethods: ["config"],
        evidence: [
          evidence(
            file.path,
            line,
            level === "normal"
              ? "protectionLevel is normal."
              : "No protectionLevel is set, so Android defaults it to normal.",
          ),
        ],
        attackScenario: "Any app can request and receive this permission, then call components that depend on it.",
        preconditions: ["A component or API treats this permission as an access boundary."],
        why: "Normal permissions are granted to requesting apps and do not identify the caller.",
        recommendation: "Use protectionLevel signature for permissions that should only be held by the same signing key.",
        recipe: "manual",
        masvs: [],
        fingerprintSource: `permission:${name}:${level ?? "default"}`,
      }),
    );
  }
  return found;
}

function classFile(files: SourceFile[], className: string): SourceFile | undefined {
  const simple = className.split(".").pop() ?? className;
  return files.find(
    (file) =>
      /\.(kt|java)$/.test(file.path) && new RegExp(`\\b(?:class|object|interface)\\s+${simple}\\b`).test(file.text),
  );
}

function manifestDrafts(file: SourceFile, files: SourceFile[]): Draft[] {
  if (!file.path.endsWith("AndroidManifest.xml")) return [];
  const manifest = parseManifest(file.path, file.text);
  const found: Draft[] = [];
  found.push(...scanManifestPolicy(file));
  if (manifest.debuggable) {
    const line = lineAt(file.text, file.text.search(/android:debuggable\s*=\s*"true"/));
    found.push(
      draft({
        ruleId: "ANDROID-DEBUGGABLE",
        title: "Manifest marks the application debuggable",
        language: "xml",
        path: file.path,
        line,
        severity: "P1",
        confidence: "high",
        category: "build",
        detectionMethods: ["config"],
        evidence: [evidence(file.path, line, "android:debuggable is true.")],
        attackScenario: "If this value survives the release merge, the shipped app can be debugged.",
        preconditions: ["A build type does not override this attribute to false for the artifact under review."],
        why: "The manifest explicitly requests a debug runtime.",
        recommendation: "Remove android:debuggable from the manifest and set it only on the debug build type.",
        recipe: "automatic",
        masvs: ["MASVS-RESILIENCE"],
        fingerprintSource: "manifest-debuggable",
      }),
    );
  }
  if (manifest.allowBackup) {
    const line = lineAt(file.text, file.text.search(/android:allowBackup\s*=\s*"true"/));
    found.push(
      draft({
        ruleId: "ANDROID-BACKUP",
        title: "Application backup is enabled without an extraction rule in this manifest",
        language: "xml",
        path: file.path,
        line,
        severity: "P3",
        confidence: "low",
        category: "storage",
        detectionMethods: ["config"],
        evidence: [evidence(file.path, line, "android:allowBackup is true.")],
        attackScenario: "A backup may include files the application did not intend to leave the device.",
        preconditions: ["No data extraction rules exclude sensitive files, and the app stores secrets in backed-up locations."],
        why: "Full backup copies application data unless extraction rules narrow it.",
        recommendation: "Review backup contents. Exclude credential stores, or disable backup if the product does not need it.",
        recipe: "automatic",
        masvs: ["MASVS-STORAGE"],
        fingerprintSource: "allow-backup",
      }),
    );
  }
  if (manifest.usesCleartextTraffic) {
    const line = lineAt(file.text, file.text.search(/android:usesCleartextTraffic\s*=\s*"true"/));
    found.push(
      draft({
        ruleId: "NETWORK-CLEARTEXT",
        title: "Application allows cleartext traffic",
        language: "xml",
        path: file.path,
        line,
        severity: "P2",
        confidence: "high",
        category: "network",
        detectionMethods: ["config"],
        evidence: [evidence(file.path, line, "usesCleartextTraffic is true on the application element.")],
        attackScenario: "Http requests from this application can be observed and changed on the network.",
        preconditions: ["The release variant still contacts servers over http."],
        why: "The manifest opts the application out of the cleartext restriction.",
        recommendation: "Set usesCleartextTraffic to false after confirming every production endpoint uses https.",
        recipe: "automatic",
        masvs: ["MASVS-NETWORK"],
        fingerprintSource: `cleartext:${file.path}`,
      }),
    );
  }

  for (const component of manifest.components) {
    if (component.exported === false || isLauncher(component)) continue;
    const exposed = component.exported === true || (component.exported === "unspecified" && component.actions.length > 0);
    if (!exposed) continue;
    const implementation = classFile(files, component.name);
    const protectedOnly = component.kind === "receiver" && onlyProtectedBroadcasts(component);
    let severity: Severity = component.kind === "provider" && component.grantUriPermissions ? "P1" : "P2";
    let confidence: Confidence = "medium";
    const items: Evidence[] = [
      evidence(
        file.path,
        component.line,
        component.exported === true
          ? `${component.kind} ${component.name} is exported.`
          : `${component.kind} ${component.name} has an intent filter and does not set android:exported.`,
      ),
    ];
    if (component.permission) {
      items.push(evidence(file.path, component.line, `A permission is declared: ${component.permission}.`));
      confidence = "low";
      severity = "informational";
    }
    if (protectedOnly) {
      severity = "informational";
      confidence = "low";
      items.push(evidence(file.path, component.line, "The receiver listens only for protected system broadcasts."));
    }
    if (implementation) {
      items.push(evidence(implementation.path, 1, `Implementation is ${implementation.path}.`));
      const usesExternal =
        /getIntent\s*\(|intent\?\.data|getStringExtra|getQueryParameter|getData\(/.test(implementation.text);
      const hasAuth = AUTH_MARKERS.test(implementation.text);
      if (usesExternal && hasAuth) {
        confidence = "medium";
        severity = severity === "informational" ? severity : "P2";
        items.push(evidence(implementation.path, 1, "An authorization API is present, so this was not promoted to high confidence."));
      } else if (usesExternal && !component.permission && !protectedOnly) {
        confidence = "high";
        severity = severityAtLeast(severity, "P1");
        items.push(
          evidence(
            implementation.path,
            lineAt(implementation.text, implementation.text.search(/getIntent\s*\(|getStringExtra|getQueryParameter|getData\(/)),
            "External input is read and no authorization API was found in this file.",
          ),
        );
      } else if (component.kind === "provider" && /fun query|public Cursor query/.test(implementation.text) && !hasAuth && !component.permission) {
        confidence = "high";
        severity = severityAtLeast(severity, "P1");
        items.push(evidence(implementation.path, 1, "The provider implements query without an authorization API in this file."));
      }
    } else {
      items.push(evidence(file.path, component.line, "The component implementation was not found in the scanned sources."));
    }

    if (confidence === "low" && severity === "informational" && component.permission) {
      continue;
    }

    const posture = !implementation ? "missing" : AUTH_MARKERS.test(implementation.text) ? "auth" : "no-auth";
    const ruleId = component.exported === "unspecified" ? "ANDROID-IMPLICIT-EXPORT" : "ANDROID-EXPORTED-COMPONENT";
    found.push(
      draft({
        ruleId,
        title:
          ruleId === "ANDROID-IMPLICIT-EXPORT"
            ? `Intent filter without android:exported on ${component.name}`
            : `Exported ${component.kind} ${component.name}`,
        language: "xml",
        path: file.path,
        line: component.line,
        severity,
        confidence,
        category: "platform",
        detectionMethods: implementation ? ["config", "cross-file"] : ["config"],
        evidence: items,
        attackScenario: protectedOnly
          ? "Third-party apps generally cannot send this protected broadcast. Review custom actions added later."
          : `Another app can start ${component.name} if the component is enabled and no stronger permission blocks it.`,
        preconditions: [
          "The component remains enabled in the merged manifest.",
          component.permission ? "The declared permission does not actually restrict untrusted callers." : "No effective permission or authorization check was identified.",
        ],
        why: "Exported Android components are part of the application's external attack surface.",
        recommendation: component.permission
          ? "Confirm the permission protection level is signature or a stronger internal check."
          : "Set android:exported to false unless another app must call this component. If it must, require a signature permission and authorize the operation in code.",
        recipe: "manual",
        masvs: ["MASVS-PLATFORM"],
        subject: component.name,
        fingerprintSource: `${component.kind}:${component.name}:${component.exported}:${posture}`,
      }),
    );
  }
  return found;
}

function commented(snippet: string): boolean {
  const trimmed = snippet.trim();
  return trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("#") || trimmed.startsWith("--");
}

function scanPolyglot(file: SourceFile): Draft[] {
  const language = languageOf(file.path);
  if (!language) return [];
  const text = file.text;
  const found: Draft[] = [];
  const push = (ruleId: string, title: string, match: { index: number; line: number; snippet: string }, category: Draft["category"], why: string, recommendation: string, evidenceText: string) => {
    if (commented(match.snippet)) return;
    found.push(
      draft({
        ruleId,
        title,
        language,
        path: file.path,
        line: match.line,
        severity: "P1",
        confidence: "high",
        category,
        detectionMethods: ["pattern"],
        evidence: [evidence(file.path, match.line, evidenceText)],
        attackScenario: "The insecure call is in the app only when that code runs.",
        preconditions: ["The recorded call is part of the shipped app."],
        why,
        recommendation,
        recipe: "manual",
        masvs: [],
        fingerprintSource: `${ruleId}:${match.index}`,
      }),
    );
  };

  if (language === "c" || language === "cpp") {
    for (const match of matchesIn(text, /\b(?:gets|strcpy|strcat|sprintf|vsprintf|mktemp)\s*\(/g)) {
      push(
        "CODE-NATIVE-UNSAFE",
        "Native call does not bound its buffer",
        match,
        "injection",
        "gets, strcpy, strcat, sprintf, vsprintf, and mktemp do not limit how much they write.",
        "Use a bounded call such as snprintf or a C++ string. Keep the same data moving to the same caller.",
        "An unbounded native copy or formatting call is used.",
      );
    }
    for (const match of matchesIn(text, /\b(?:system|popen)\s*\(/g)) {
      push(
        "CODE-NATIVE-EXEC",
        "Native code starts a shell command",
        match,
        "injection",
        "system and popen pass text to a shell.",
        "Call the specific program with a fixed argument list. Do not build a shell string. Keep the same task the user started.",
        "system or popen is called.",
      );
    }
  }

  if (language === "csharp" && /ServerCertificate(?:CustomValidationCallback|ValidationCallback)/.test(text) && /return\s+true|=>\s*true/.test(text)) {
    const match = matchesIn(text, /ServerCertificate(?:CustomValidationCallback|ValidationCallback)/g)[0];
    if (match) {
      push(
        "NETWORK-DOTNET-TRUST-ALL",
        ".NET HTTP handler accepts any certificate",
        match,
        "network",
        "A certificate callback that returns true accepts every server certificate.",
        "Delete the callback and use the platform trust decision. Keep the same request and response handling.",
        "A .NET certificate callback is paired with a true result.",
      );
    }
  }

  if (language === "python") {
    for (const match of matchesIn(text, /verify\s*=\s*False|_create_unverified_context\s*\(/g)) {
      push(
        "NETWORK-PYTHON-UNVERIFIED",
        "Python TLS check is disabled",
        match,
        "network",
        "verify=False and an unverified SSL context skip certificate checks.",
        "Leave verification on. Keep the same URL and the same response handling.",
        "A Python HTTP or TLS call skips certificate verification.",
      );
    }
    for (const match of matchesIn(text, /pickle\.loads\s*\(/g)) {
      push(
        "CODE-PYTHON-PICKLE",
        "Python unpickles data",
        match,
        "injection",
        "pickle.loads runs objects stored in the pickle stream.",
        "Read a plain data format such as JSON. Keep the same fields the screen already uses.",
        "pickle.loads is called.",
      );
    }
  }

  if (language === "rust") {
    for (const match of matchesIn(text, /danger_accept_invalid_certs\s*\(\s*true\s*\)/g)) {
      push(
        "NETWORK-RUST-INVALID-CERTS",
        "Rust TLS client accepts invalid certificates",
        match,
        "network",
        "danger_accept_invalid_certs(true) turns certificate checks off.",
        "Remove that call and use the default rustls verifier. Keep the same request.",
        "danger_accept_invalid_certs(true) is set.",
      );
    }
  }

  if (language === "ruby") {
    for (const match of matchesIn(text, /VERIFY_NONE/g)) {
      push(
        "NETWORK-RUBY-VERIFY-NONE",
        "Ruby TLS verification is disabled",
        match,
        "network",
        "VERIFY_NONE accepts any certificate.",
        "Use VERIFY_PEER. Keep the same request and response handling.",
        "VERIFY_NONE is used.",
      );
    }
  }

  if (language === "lua") {
    for (const match of matchesIn(text, /\bos\.execute\s*\(|\bloadstring\s*\(/g)) {
      push(
        "CODE-LUA-DYNAMIC",
        "Lua runs a command or loads code from text",
        match,
        "injection",
        "os.execute starts a shell command. loadstring runs text as code.",
        "Call a fixed function for the same game or app step. Do not pass outside text to os.execute or loadstring.",
        "os.execute or loadstring is called.",
      );
    }
  }

  return found;
}

export function findingsForFile(file: SourceFile, files: SourceFile[]): Draft[] {
  return [
    ...manifestDrafts(file, files),
    ...scanSource(file),
    ...scanDart(file),
    ...scanScript(file),
    ...scanGradle(file),
    ...scanXmlConfig(file),
    ...scanPolyglot(file),
    ...(file.path.endsWith("package.json") ? dependencyFindings(file) : []),
  ];
}

export function ruleStillMatches(ruleId: string, file: SourceFile, files: SourceFile[]): boolean {
  return findingsForFile(file, files).some((item) => item.ruleId === ruleId);
}
