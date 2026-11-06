# What we are building

SecureDroid is a local Android secure-coding agent. A developer opens an Android, Flutter, or React Native project in Oh My Pi. The agent reads the code, names the vulnerabilities it can support with evidence, explains what is true when that code ships, recommends a fix, and stages the safe ones. The developer accepts or rejects each change.

The goal is a harness a developer can trust while editing, not a scanner that dumps every suspicious API and rewrites the project on its own.

## Goal

When the harness is doing its job:

- Rules and the model share one finding record. The model cannot invent a line, raise a guess to confirmed, or mark its own patch as accepted.
- A finding is called a vulnerability only after the current source still matches and a call path or build setting shows that it applies.
- The runtime label describes exposure from the source. It does not include exploit steps, payloads, or proof-of-concept requests.
- Insecure coding is removed by a staged patch with a known meaning, or by a recommendation when the change needs a person. Crypto, secrets, and authorization checks are recommendations.
- A fix is not called done until the original check no longer matches. A build that was not run is reported as `partial`, which is not a pass.
- Semgrep is required. The Sigma and YARA packs run on every scan. ast-grep is an extra structural scanner. A missing tool is unavailable, not a pass. An external match that our own rule does not confirm is dropped.

## What this is for

SecureDroid is for the person writing the app. It reviews Kotlin, Java, Jetpack Compose, Gradle, manifests, Flutter, and React Native in one loop. `/android-scan` is the one pass: deterministic rules, required Semgrep, Sigma, YARA, and the source. The model gives the end result from that context. The developer accepts or rejects a staged fix.

It is not a penetration test, a dashboard, a CI gate, or a hosted model. Oh My Pi supplies the editor and the model. SecureDroid supplies the Android judgment.

## What "done" does not mean

An app with no upheld findings is not MASVS-compliant. Authentication, certificate pinning, update enforcement, tamper checks, obfuscation, and privacy-policy text need product context, so they are not default findings. Dependency versions use one local OSV snapshot. A package missing from that snapshot is not a pass. The call path is read from source. The app is not installed on a device.

Those limits stay visible in the report. Closing them is future work. Hiding them is not the goal.
