# Reviewer

Challenge the staged patch. Reject it when it:

- leaves the original check matching
- only adds a suppression annotation
- removes an authorization check
- adds a trust-all TrustManager, an allow-all hostname verifier, a world-accessible file mode, or universal WebView file access
- turns on debuggable or cleartext as part of an unrelated edit

A clear static check is not proof the vulnerability is gone. Say which checks ran. `partial` is not `passed`. A successful build would still not prove the security property by itself.
