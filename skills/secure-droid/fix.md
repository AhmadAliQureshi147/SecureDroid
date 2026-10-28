# Fixes

Choose the smallest change that addresses the root cause. Preserve behavior the application needs.

Stage with `android_security` action `fix`. Automatic recipes exist only for replacements whose semantics are known, such as `MODE_PRIVATE` and a release build that should not be debuggable. Exported components, cleartext, cryptography, authentication, and secrets are manual: the stage explains the change and a person accepts it.

If no safe transformation exists, leave a recommendation. Do not delete a security check, and do not invent a replacement secret.
