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
- Insecure-coding pass for obsolete TLS, `setEnabledProtocols` with SSL or TLS 1.0/1.1, unsafe `Intent.parseUri`, dex class loaders, `CONTEXT_IGNORE_SECURITY`, `CONTEXT_INCLUDE_CODE`, `System.load`, a fixed `SecureRandom` seed, `Cipher.getInstance("AES")`, HTTP body logging, WebView safe browsing turned off, FileProvider root paths, `sharedUserId`, `allowTaskReparenting`, and world-readable file modes including numeric `openFileOutput` modes. The model reads the runtime field for each and records a variant the rules missed.
- Review brain. The configured model is Grok 4.7. Put the Cursor API key in the gitignored `.env` file as `CURSOR_API_KEY`. `npm run omp` loads that file. The key is not written into source, findings, or this README.
- Source read. `/android-review` and `android_security` action `read` show the project source, page by page, for Kotlin, Java, C, C++, C#, Dart, JavaScript, TypeScript, Python, Rust, Ruby, Lua, HTML, CSS, Groovy, Gradle Kotlin DSL, and XML. Each page lists the lines the rules already recorded. The model learns what that directory does, reviews every other line, records a miss, and continues to the next line. A staged fix has to keep the same screen, data, and user step. The review is not finished until the last page. Secrets in assignments are redacted.
- Code map. When `graphify` is installed, `/android-review` builds a local map of calls and imports before the model judges a line. An EXTRACTED path names the files to read. An INFERRED path stays unconfirmed. The map does not decide a vulnerability and does not edit source.

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
- `debuggable` is turned off inside the release build type, and `android:debuggable` is turned off on the manifest line
- `android:allowBackup="true"` becomes `false` on the finding line
- `FLAG_IMMUTABLE` is added to a same-line `PendingIntent` factory call
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

The code map is optional. Install the `graphify` command, or the local virtualenv `.tools/graphify-venv`, and `/android-review` will build it with `GRAPHIFY_BACKEND=none` so the code is parsed locally:

```bash
uv tool install graphifyy
```

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

### Windows

Install Node.js 22.18 or newer, Git for Windows, and [Bun](https://bun.sh). Android Studio does not need to be open. Use the project folder that contains `AndroidManifest.xml` and Gradle, `pubspec.yaml` for Flutter, or `package.json` for React Native.

Open **Git Bash** and clone both repositories:

```bash
git clone https://github.com/AhmadAliQureshi147/SecureDroid.git
cd SecureDroid
git clone --depth 1 https://github.com/can1357/oh-my-pi.git oh-my-pi
cd oh-my-pi && bun install && cd ..
npm install
```

Start the chat agent from Git Bash. `npm run omp` needs Bash.

```bash
npm run omp -- /c/Users/you/AndroidStudioProjects/YourApp
```

Inside the session, run `/android-scan` and then `/android-review`. The planted sample is:

```bash
npm run omp -- fixtures/native-android
```

A scan without the chat agent works in PowerShell:

```powershell
node --experimental-strip-types src/cli.ts scan C:\Users\you\AndroidStudioProjects\YourApp
```

Optional on Windows: `pip install semgrep` and leave `semgrep` on your PATH. `@ast-grep/cli` is installed by `npm install`. A missing scanner is reported as unavailable and is not treated as a pass.

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
- `partial` — the static check no longer matches, the patched file's delimiters balance, and the build was not run
- `failed` — the patched file has a broken delimiter
- `blocked` or `failed` — the patch is stale, unsafe, or the original check still matches
- `passed` — not used, because the build and tests were not run

`partial` is not a pass. SecureDroid does not run Gradle, Android Lint, or project tests, because those commands execute repository code.

## Standards

The `masvs` field names the MASVS v2 requirement a check relates to. Covered areas include storage, cryptography, network, platform IPC, WebView, input validation, backup and log leakage, clipboard disclosure, and debuggable release builds.

These requirements are not default findings, because a pattern cannot establish them:

- Authentication and step-up (`MASVS-AUTH-1` through `MASVS-AUTH-3`)
- Certificate pinning (`MASVS-NETWORK-2`), which is hardening
- Minimum SDK and forced updates (`MASVS-CODE-1` and `MASVS-CODE-2`). Dependency versions are compared with the local OSV snapshot (`MASVS-CODE-3`). A package that is not in the snapshot is not a pass.
- Tamper checks and obfuscation (`MASVS-RESILIENCE-1` through `MASVS-RESILIENCE-3`)
- Privacy notices and user control (`MASVS-PRIVACY-2` through `MASVS-PRIVACY-4`)

## Tests

```bash
npm test
```

`fixtures/` holds planted vulnerabilities and safe counterparts. The clean fixture must not produce a `P0`, `P1`, or `P2` finding.

## Limits

SecureDroid does not discover every vulnerability and it does not replace a penetration test. An empty scan does not mean the app meets MASVS. The advisory check is a local OSV snapshot, not every published advisory. There is no CI gate, dashboard, or hosted model. The Oh My Pi provider you configure handles model traffic.
