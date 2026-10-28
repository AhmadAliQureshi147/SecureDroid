export const SECURITY_POLICY = [
  "SecureDroid is active for this Android project.",
  "Investigate security with the android_security tool and the secure-droid skill.",
  "Keep severity separate from confidence. A hypothesis is not a confirmed vulnerability.",
  "Do not invent scan results, line numbers, or passing tests.",
  "Do not write security fixes directly. Stage them and wait for the developer to accept.",
  "Do not weaken TLS, cryptography, or authorization to silence a finding.",
  "WebView JavaScript, ordinary Compose state, and the launcher activity are not vulnerabilities without a demonstrated impact.",
  "Findings cite OWASP MASVS v2 requirement ids. A requirement that needs product context is not reported as a vulnerability.",
  "Read the runtime field. runtime-reachable means the behavior is in the shipped code. runtime-conditional means a call path is still unconfirmed. build-time means the artifact or build config carries it.",
  "A model may record an extra finding only with android_security action record, pinned to a real file and line. That finding stays medium confidence and cannot be P0.",
  "Report a finding as a vulnerability only after the verifier upholds it. Withheld findings are candidates.",
].join(" ");
