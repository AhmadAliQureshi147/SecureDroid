---
name: secure-droid
description: Investigate and remediate Android application security across Kotlin, Java, Jetpack Compose, Flutter, React Native, manifests, and Gradle. Use for security review, vulnerability evidence, staged fixes, and verification.
---

# SecureDroid

SecureDroid is the Android security workflow for this session. Oh My Pi reads, searches, and edits. SecureDroid decides whether a pattern is a vulnerability, records evidence, and stages fixes for the developer.

## Workflow

1. Call `android_security` with `detect`, then `map`, then `scan`.
2. Read this skill's specialist notes when that stack is present:
   - `skill://secure-droid/kotlin.md`
   - `skill://secure-droid/compose.md`
   - `skill://secure-droid/flutter.md`
   - `skill://secure-droid/react-native.md`
   - `skill://secure-droid/fix.md`
   - `skill://secure-droid/reviewer.md`
3. Call `triage`, then spawn `android-verifier`. Report only findings marked upheld. Withheld findings are not vulnerabilities yet.
4. Explain what is vulnerable, the conditions required, and what is still unknown. Keep severity separate from confidence. Do not write exploit steps.
5. If the rules missed an issue, call `record` with the file and line you read. The finding stays medium confidence and cannot be P0.
6. When the developer asks to clean the project, call `remediate` to stage every automatic recipe, or `fix` for one finding. Do not write the source file yourself.
7. Call `verify`. `partial` means the static check cleared and the build was not run. Do not describe that as a pass.
8. The developer accepts or rejects the stage with `/android-accept` or `/android-reject`.
9. On a hard call-path question, spawn `android-runtime` or `android-reviewer`. Spawn `android-fixer` only when the developer asked for fixes.

## Judgment

- A deterministic match is a candidate. Confirm it from the surrounding code.
- An exported launcher activity is expected. An exported component with a permission was not promoted.
- `javaScriptEnabled` alone is not a vulnerability. A JavaScript interface, file access, or an untrusted URL changes that.
- Compose state and recomposition are not vulnerabilities without a shown disclosure or missing authorization check.
- Flutter and React Native reviews include the inner `android/` project.
- Do not invent a line number, a permission, a scanner result, or a passing test.
- Do not turn off TLS, certificate checks, or authorization to make a warning disappear.
- Do not claim MASVS coverage beyond the `masvs` field on a finding.
- Missing tools are unavailable, not passed.

## Confidence

- `confirmed`: the code itself establishes the failure, such as an empty certificate check.
- `high`: strong evidence, with one relevant condition still unverified.
- `medium`: plausible, needs more of the call path.
- `low`: a hypothesis. Do not present it as an actionable vulnerability.
