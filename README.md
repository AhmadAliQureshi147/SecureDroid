# SecureDroid

SecureDroid is an Android secure-coding harness for [Oh My Pi](https://github.com/can1357/oh-my-pi). The model reads the project. SecureDroid decides which matches are vulnerabilities, records evidence, stages a fix, and checks that fix before any source file changes.

Repository: [github.com/AhmadAliQureshi147/SecureDroid](https://github.com/AhmadAliQureshi147/SecureDroid)

What this project is trying to become is written in [docs/README.md](docs/README.md).

Android Studio does not need to be open. Point the commands below at the project folder on disk.

## Features

- One review loop for Kotlin, Java, Jetpack Compose, manifests, Gradle, network security config, Flutter (including `android/`), and React Native (including native modules).
- Deterministic rules mapped to [OWASP MASVS](https://mas.owasp.org/MASVS/) v2. Severity (`P0`–`P3`) stays separate from confidence (`confirmed`, `high`, `medium`, `low`).
- A call-path label on every finding: `runtime-reachable`, `runtime-conditional`, or `build-time`. The label follows a launcher or exported component through the source. It is not a device run and not an exploit procedure.
- A verifier. `/android-triage` reports a finding as a vulnerability only when the check still matches and the call path or build setting supports it. Weaker matches are withheld. The model cannot dismiss a finding while the rule still matches.
- The model can add a finding only with `record`, pinned to a real file and line. That finding stays medium confidence and cannot be `P0`.
- Staged fixes. Source stays unchanged until you accept a stage. The model tool cannot accept its own patch.
- Open-source scanners. Semgrep and ast-grep run when installed. A match is kept only when it names a SecureDroid rule and the built-in rule still matches that file.
- Write guard. The session blocks new trust-all certificate checks, allow-all hostname verifiers, ignored TLS errors, world-readable file modes, and universal WebView file access.
- Secret redaction, path confinement, and fingerprint-scoped exceptions. An exception expires when the evidence changes.

The launcher activity, a WebView with JavaScript enabled, and ordinary Compose state are not findings by themselves.

## Harness

`npm run omp` starts the Oh My Pi checkout in your app directory, loads this extension, and appends `prompts/harness.md` to the system prompt.

| Agent | Job | Writes source |
|---|---|---|
| `android-security` | Leads detect, map, and scan | No |
| `android-runtime` | Explains what the running app exposes from the call path | No |
| `android-verifier` | Upholds or withholds findings after reading the evidence | No |
| `android-reviewer` | Checks a call path the rules left uncertain and records line-pinned investigations | No |
| `android-fixer` | Stages fixes through `android_security` | No |

Extension tools stay available to those agents. Built-in write tools are not given to the fixer, verifier, runtime agent, or reviewer. Fixes go through `android_security`.

Slash commands inside the session:

- `/android-detect`
- `/android-map`
- `/android-scan`
- `/android-triage`
- `/android-review`
- `/android-investigate <finding-id>`
- `/android-fix <finding-id>`
- `/android-remediate`
- `/android-verify <finding-id>`
- `/android-findings`
- `/android-accept <finding-id>`
- `/android-reject <finding-id>`
- `/android-except <finding-id> <reason>`

`/android-remediate` stages every automatic recipe. It does not accept patches.

Automatic patches:

- `MODE_WORLD_READABLE` and `MODE_WORLD_WRITEABLE` become `MODE_PRIVATE`
- `debuggable` is turned off inside the release build type only
- cleartext is turned off on the finding line
- `setWebContentsDebuggingEnabled(true)` becomes `false`
- `MIXED_CONTENT_ALWAYS_ALLOW` becomes `MIXED_CONTENT_NEVER_ALLOW`

Crypto, secrets, WebView bridges, and exported components stay recommendations. Accepting an exported-component or manifest-debug patch still needs a developer decision when one is staged.

## Setup

Requirements:

- Node.js 22.18 or newer
- An Android, Flutter, or React Native project directory
- [Bun](https://bun.sh) for the Oh My Pi session

```bash
git clone https://github.com/AhmadAliQureshi147/SecureDroid.git
cd SecureDroid
git clone --depth 1 https://github.com/can1357/oh-my-pi.git oh-my-pi
cd oh-my-pi && bun install && cd ..
npm install
```

Optional scanners, used when the binaries are available:

```bash
python3 -m pip install semgrep
```

`@ast-grep/cli` is a dev dependency. Semgrep is also detected at `.tools/venv/bin/semgrep` when that virtualenv exists. A missing scanner is reported as unavailable. It is not treated as a pass.

### Run the agent

```bash
npm run omp -- /path/to/your-android-project
```

Use the folder that contains `app/src/main/AndroidManifest.xml` and a Gradle build file. Flutter uses the folder with `pubspec.yaml`. React Native uses the folder with `package.json`.

Inside the session:

```text
/android-scan
/android-review
```

The included sample, which contains planted bugs, is:

```bash
npm run omp -- fixtures/native-android
```

`oh-my-pi/securedroid.sh` launches the same session from inside the Oh My Pi checkout.

### Run a scan without the chat agent

```bash
node --experimental-strip-types src/cli.ts detect /path/to/android-app
node --experimental-strip-types src/cli.ts scan /path/to/android-app
node --experimental-strip-types src/cli.ts remediate /path/to/android-app
node --experimental-strip-types src/cli.ts fix <finding-id> /path/to/android-app
node --experimental-strip-types src/cli.ts accept <finding-id> /path/to/android-app
```

Findings and exceptions are stored in `<app>/.secure-droid/store.json`. `fix` writes a staged patch there. `accept` saves it only when the review is not blocked and the file still matches the scanned bytes. `reject` discards the stage and leaves source unchanged.

## Architecture

```text
Oh My Pi session
  prompts/harness.md          session rules
  agents/                     security, runtime, verifier, fixer, reviewer
  skills/secure-droid/        stack notes for Kotlin, Compose, Flutter, React Native
        |
        v
android_security tool        src/index.ts
        |
        v
engine                       detect, map, scan, triage, judge, fix, verify
        |
        +-- rules.ts         deterministic checks
        +-- standards.ts     MASVS v2 ids, including requirements that are not findings
        +-- runtime.ts       call path from a launcher or exported component
        +-- engines/         semgrep and ast-grep packs
        +-- triage.ts        upheld, withheld, or rejected
        +-- patch.ts         staged diffs and review blocks
        +-- guard.ts         blocks new insecure edits
        +-- store.ts         .secure-droid/store.json
```

A scan collects source, runs the built-in rules, merges confirmed external matches, then triages. The report lists upheld findings as vulnerabilities. Withheld findings stay visible as candidates.

Verification of a staged fix:

- `not-run` — no source patch, or the check did not run
- `partial` — the static check no longer matches, and the build was not run
- `blocked` or `failed` — the patch is stale, unsafe, or the original check still matches
- `passed` — not used, because the build and tests were not run

`partial` is not a pass. SecureDroid does not run Gradle, Android Lint, or project tests, because those commands execute repository code.

## Standards

The `masvs` field names the MASVS v2 requirement a check relates to. Covered areas include storage, cryptography, network, platform IPC, WebView, input validation, backup and log leakage, clipboard disclosure, and debuggable release builds.

These requirements are not default findings, because a pattern cannot establish them:

- Authentication and step-up (`MASVS-AUTH-1` through `MASVS-AUTH-3`)
- Certificate pinning (`MASVS-NETWORK-2`), which is hardening
- Minimum SDK, forced updates, and dependency advisories (`MASVS-CODE-1` through `MASVS-CODE-3`)
- Tamper checks and obfuscation (`MASVS-RESILIENCE-1` through `MASVS-RESILIENCE-3`)
- Privacy notices and user control (`MASVS-PRIVACY-2` through `MASVS-PRIVACY-4`)

## Tests

```bash
npm test
```

`fixtures/` holds planted vulnerabilities and safe counterparts. The clean fixture must not produce a `P0`, `P1`, or `P2` finding.

## Limits

SecureDroid does not discover every vulnerability and it does not replace a penetration test. An empty scan does not mean the app meets MASVS. Dependency versions are not compared with an advisory database. There is no CI gate, dashboard, or hosted model. The Oh My Pi provider you configure handles model traffic.
