---
name: securedroid-no-trust-all
description: Refuse a TrustManager or hostname verifier that accepts every certificate
condition: "checkServerTrusted\\s*\\([^)]*\\)\\s*\\{\\s*\\}|boolean\\s+verify\\s*\\([^)]*\\)\\s*\\{\\s*return\\s+true|HostnameVerifier\\s*\\{\\s*_\\s*,\\s*_\\s*->\\s*true|onReceivedSslError[\\s\\S]{0,200}handler\\.proceed"
scope: "tool:edit, tool:write"
---

Do not add a TrustManager with an empty checkServerTrusted, and do not make HostnameVerifier.verify return true. Use the platform trust and hostname checks.
