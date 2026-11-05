export interface Standard {
  masvs: string[];
  summary: string;
}

export const MASVS_REQUIREMENTS = [
  "MASVS-STORAGE-1",
  "MASVS-STORAGE-2",
  "MASVS-CRYPTO-1",
  "MASVS-CRYPTO-2",
  "MASVS-AUTH-1",
  "MASVS-AUTH-2",
  "MASVS-AUTH-3",
  "MASVS-NETWORK-1",
  "MASVS-NETWORK-2",
  "MASVS-PLATFORM-1",
  "MASVS-PLATFORM-2",
  "MASVS-PLATFORM-3",
  "MASVS-CODE-1",
  "MASVS-CODE-2",
  "MASVS-CODE-3",
  "MASVS-CODE-4",
  "MASVS-RESILIENCE-1",
  "MASVS-RESILIENCE-2",
  "MASVS-RESILIENCE-3",
  "MASVS-RESILIENCE-4",
  "MASVS-PRIVACY-1",
  "MASVS-PRIVACY-2",
  "MASVS-PRIVACY-3",
  "MASVS-PRIVACY-4",
] as const;

/** Pattern checks implemented by SecureDroid, mapped to MASVS v2 requirement ids. */
export const STANDARDS: Record<string, Standard> = {
  "SECRET-PRIVATE-KEY": { masvs: ["MASVS-STORAGE-1", "MASVS-CRYPTO-2"], summary: "Private key material is embedded in the repository." },
  "SECRET-HARDCODED": { masvs: ["MASVS-STORAGE-1"], summary: "A credential literal is assigned in source." },
  "STORAGE-WORLD-ACCESSIBLE": { masvs: ["MASVS-STORAGE-1"], summary: "A file is created with a world-accessible mode." },
  "STORAGE-PREFS-SECRET": { masvs: ["MASVS-STORAGE-1"], summary: "A credential-like value is written to unencrypted preferences." },
  "STORAGE-ASYNC-SECRET": { masvs: ["MASVS-STORAGE-1"], summary: "A credential-like value is written to AsyncStorage." },
  "STORAGE-EXTERNAL": { masvs: ["MASVS-STORAGE-1"], summary: "Sensitive data is written toward external storage." },
  "STORAGE-LEGACY-EXTERNAL": { masvs: ["MASVS-STORAGE-1"], summary: "The app opts back into legacy external storage." },
  "STORAGE-PROVIDER-PATH": { masvs: ["MASVS-STORAGE-1"], summary: "A FileProvider path exposes the filesystem root or an unrestricted path." },
  "BUILD-SIGNING-SECRET": { masvs: ["MASVS-STORAGE-1", "MASVS-CRYPTO-2"], summary: "A signing password is stored in Gradle." },
  "ANDROID-BACKUP": { masvs: ["MASVS-STORAGE-2"], summary: "Backup is enabled without an extraction rule in the manifest." },
  "PRIVACY-LOG": { masvs: ["MASVS-STORAGE-2", "MASVS-PRIVACY-1"], summary: "A log statement includes a credential or session value." },
  "PRIVACY-CLIPBOARD": { masvs: ["MASVS-STORAGE-2", "MASVS-PLATFORM-3", "MASVS-PRIVACY-1"], summary: "A credential or session value is copied to the clipboard." },
  "CRYPTO-ECB": { masvs: ["MASVS-CRYPTO-1"], summary: "A cipher uses ECB." },
  "CRYPTO-STATIC-IV": { masvs: ["MASVS-CRYPTO-1"], summary: "An initialization vector is a fixed zero block." },
  "CRYPTO-WEAK-PASSWORD-HASH": { masvs: ["MASVS-CRYPTO-1"], summary: "A password is hashed with MD5." },
  "CRYPTO-WEAK-ALGORITHM": { masvs: ["MASVS-CRYPTO-1"], summary: "A broken or obsolete cipher algorithm is requested." },
  "CRYPTO-INSECURE-RANDOM": { masvs: ["MASVS-CRYPTO-1"], summary: "java.util.Random is used for key or IV material." },
  "CRYPTO-HARDCODED-KEY": { masvs: ["MASVS-CRYPTO-2"], summary: "A cipher key is a string literal." },
  "NETWORK-TRUST-ALL": { masvs: ["MASVS-NETWORK-1"], summary: "Server certificate validation is empty." },
  "NETWORK-HOSTNAME-VERIFIER": { masvs: ["MASVS-NETWORK-1"], summary: "Hostname verification always succeeds." },
  "NETWORK-CLEARTEXT": { masvs: ["MASVS-NETWORK-1"], summary: "Cleartext traffic is permitted." },
  "NETWORK-USER-CA": { masvs: ["MASVS-NETWORK-1"], summary: "User-installed certificate authorities are trusted outside debug overrides." },
  "NETWORK-SSL-ERROR-PROCEED": { masvs: ["MASVS-NETWORK-1", "MASVS-PLATFORM-2"], summary: "A WebView SSL error is ignored with proceed()." },
  "NETWORK-MIXED-CONTENT": { masvs: ["MASVS-NETWORK-1", "MASVS-PLATFORM-2"], summary: "The WebView always allows mixed content." },
  "NETWORK-WEAK-TLS": { masvs: ["MASVS-NETWORK-1"], summary: "TLS is configured to an obsolete protocol." },
  "FLUTTER-BAD-CERTIFICATE": { masvs: ["MASVS-NETWORK-1"], summary: "A Dart HTTP client accepts any certificate." },
  "ANDROID-EXPORTED-COMPONENT": { masvs: ["MASVS-PLATFORM-1"], summary: "An exported component is reachable beyond the app." },
  "ANDROID-IMPLICIT-EXPORT": { masvs: ["MASVS-PLATFORM-1"], summary: "An intent filter does not set android:exported." },
  "PLATFORM-INTENT-REDIRECT": { masvs: ["MASVS-PLATFORM-1"], summary: "A nested intent from an extra is started." },
  "PLATFORM-MUTABLE-PENDING-INTENT": { masvs: ["MASVS-PLATFORM-1"], summary: "A PendingIntent is created without FLAG_IMMUTABLE." },
  "PLATFORM-NORMAL-PERMISSION": { masvs: ["MASVS-PLATFORM-1"], summary: "A custom permission uses protection level normal, or omits it." },
  "PLATFORM-PARSE-URI": { masvs: ["MASVS-PLATFORM-1"], summary: "Intent.parseUri is called with an unsafe URI flag." },
  "PLATFORM-SHARED-USER-ID": { masvs: ["MASVS-PLATFORM-1"], summary: "The manifest sets a shared user id." },
  "INJECTION-COMMAND": { masvs: ["MASVS-CODE-4", "MASVS-PLATFORM-1"], summary: "Command execution receives a non-literal or bridge argument." },
  "WEBVIEW-JS-BRIDGE": { masvs: ["MASVS-PLATFORM-2"], summary: "A WebView exposes a JavaScript interface." },
  "WEBVIEW-FILE-ACCESS": { masvs: ["MASVS-PLATFORM-2"], summary: "WebView file-URL access is enabled." },
  "WEBVIEW-UNTRUSTED-URL": { masvs: ["MASVS-PLATFORM-2"], summary: "A WebView loads a URL that is not a fixed https address." },
  "WEBVIEW-JS-URL": { masvs: ["MASVS-PLATFORM-2"], summary: "A WebView loads a javascript: URL." },
  "WEBVIEW-ORIGIN-WILDCARD": { masvs: ["MASVS-PLATFORM-2"], summary: "A WebView origin allowlist is a wildcard." },
  "WEBVIEW-DEBUG": { masvs: ["MASVS-PLATFORM-2", "MASVS-RESILIENCE-4"], summary: "WebView contents debugging is enabled outside a debug guard." },
  "WEBVIEW-SAFE-BROWSING": { masvs: ["MASVS-PLATFORM-2"], summary: "WebView safe browsing is turned off." },
  "INJECTION-SQL": { masvs: ["MASVS-CODE-4"], summary: "SQL is built by concatenation or interpolation." },
  "INJECTION-ZIP-SLIP": { masvs: ["MASVS-CODE-4"], summary: "A zip entry name is used as a path without a canonical-path check." },
  "INJECTION-PATH": { masvs: ["MASVS-CODE-4"], summary: "An intent extra is used as a file path." },
  "CODE-DESERIALIZATION": { masvs: ["MASVS-CODE-4"], summary: "ObjectInputStream.readObject deserializes a stream." },
  "CODE-DYNAMIC-LOAD": { masvs: ["MASVS-CODE-4"], summary: "Dalvik bytecode is loaded with a dex class loader." },
  "CODE-PACKAGE-CONTEXT": { masvs: ["MASVS-CODE-4"], summary: "A package context ignores the other app's signature or loads its code." },
  "CODE-NATIVE-LOAD": { masvs: ["MASVS-CODE-4"], summary: "Native code is loaded from a filesystem path." },
  "CODE-NATIVE-UNSAFE": { masvs: ["MASVS-CODE-4"], summary: "Native code uses an unbounded copy or formatting call." },
  "CODE-NATIVE-EXEC": { masvs: ["MASVS-CODE-4"], summary: "Native code starts a shell command." },
  "NETWORK-DOTNET-TRUST-ALL": { masvs: ["MASVS-NETWORK-1"], summary: "A .NET HTTP handler accepts any certificate." },
  "NETWORK-PYTHON-UNVERIFIED": { masvs: ["MASVS-NETWORK-1"], summary: "A Python HTTP or TLS client skips certificate checks." },
  "CODE-PYTHON-PICKLE": { masvs: ["MASVS-CODE-4"], summary: "Python unpickles data." },
  "NETWORK-RUST-INVALID-CERTS": { masvs: ["MASVS-NETWORK-1"], summary: "A Rust TLS client accepts invalid certificates." },
  "NETWORK-RUBY-VERIFY-NONE": { masvs: ["MASVS-NETWORK-1"], summary: "A Ruby TLS client disables certificate verification." },
  "CODE-LUA-DYNAMIC": { masvs: ["MASVS-CODE-4"], summary: "Lua runs a shell command or loads code from text." },
  "CRYPTO-STATIC-SEED": { masvs: ["MASVS-CRYPTO-1"], summary: "SecureRandom is seeded from a fixed value." },
  "PLATFORM-TASK-REPARENT": { masvs: ["MASVS-PLATFORM-1"], summary: "An activity allows another task to reparent it." },
  "PRIVACY-HTTP-BODY": { masvs: ["MASVS-STORAGE-2", "MASVS-PRIVACY-1"], summary: "An HTTP logger is set to record full request and response bodies." },
  "ANDROID-DEBUGGABLE": { masvs: ["MASVS-RESILIENCE-4"], summary: "The manifest marks the application debuggable." },
  "BUILD-RELEASE-DEBUGGABLE": { masvs: ["MASVS-RESILIENCE-4"], summary: "The release build type is debuggable." },
  "DEPENDENCY-ADVISORY": { masvs: ["MASVS-CODE-3"], summary: "A declared dependency version is inside an OSV advisory range." },
  "LLM-INVESTIGATION": { masvs: ["MASVS-CODE-4"], summary: "A model finding pinned to a source line the deterministic rules did not already record." },
};

/**
 * MASVS requirements that are intentionally not default findings.
 * Authentication, privacy policy, and update enforcement need product context.
 * Missing them is not reported as a vulnerability.
 */
export const UNMAPPED_REQUIREMENTS: Array<{ id: (typeof MASVS_REQUIREMENTS)[number]; reason: string }> = [
  { id: "MASVS-AUTH-1", reason: "Login, session, and authorization protocols are investigated from the call path. No pattern alone confirms them." },
  { id: "MASVS-AUTH-2", reason: "Biometric and device-credential flows are investigated from the call path rather than flagged from an API import." },
  { id: "MASVS-AUTH-3", reason: "Step-up authentication for sensitive transactions depends on product rules." },
  { id: "MASVS-NETWORK-2", reason: "Certificate pinning is additional hardening. An app that uses the platform trust store is not reported as vulnerable for lacking pins." },
  { id: "MASVS-CODE-1", reason: "Minimum platform version is a product and device decision, not a vulnerability by itself." },
  { id: "MASVS-CODE-2", reason: "Update enforcement is a distribution control. Its absence is not a source vulnerability." },
  { id: "MASVS-RESILIENCE-1", reason: "Platform integrity attestation is product-specific and is not inferred from missing checks." },
  { id: "MASVS-RESILIENCE-2", reason: "Anti-tampering controls are not treated as proof of security, and their absence is not a vulnerability." },
  { id: "MASVS-RESILIENCE-3", reason: "Obfuscation is not a security boundary. Its absence is not reported." },
  { id: "MASVS-PRIVACY-2", reason: "User identification depends on what the product collects. It is not inferred from ordinary analytics imports." },
  { id: "MASVS-PRIVACY-3", reason: "Collection notices live in privacy text and store listings, which this source review does not judge." },
  { id: "MASVS-PRIVACY-4", reason: "User control over collected data is a product flow, not a single API pattern." },
];

export function requirementIds(ruleId: string): string[] {
  const standard = STANDARDS[ruleId];
  if (!standard) throw new Error(`No MASVS mapping for ${ruleId}`);
  return standard.masvs;
}
