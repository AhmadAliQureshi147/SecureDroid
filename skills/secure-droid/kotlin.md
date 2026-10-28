# Kotlin and Java

Read the manifest entry and the component implementation together. An exported component matters when external input reaches a privileged operation and no permission or authorization check constrains it.

Treat these as MASVS failures when the code shows them: empty certificate checks, hostname verifiers that return true, `handler.proceed()` after a WebView TLS error, ECB or DES, literal cipher keys, `java.util.Random` for IVs, world-readable files, secrets in preferences or external storage, and zip entry names used as paths. A custom permission with protection level `normal` does not protect an exported component.

Prefer platform APIs already used by the project. Do not replace a working cryptographic call with ECB, a static IV, or a custom TrustManager.

SQL built with string concatenation should become a bound query. Do not keep the concatenation and add a suppression annotation.
