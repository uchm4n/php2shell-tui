# PHP2Shell-TUI — Correct Detection and Parametric RCE Verification

| | |
|---|---|
| **Status** | Draft for review |
| **Date** | 2026-10-26 |
| **Branch** | `fix/php2shell-parametric-chain` |
| **Supersedes** | The "do not exploit" decision in `.opencode/specs/2026-10-22-php2scan-design.md`; all uncalibrated profiles and guess mode |
| **Covers** | `php2shell` detection, `--verify` real exploit execution, profile selection, CLI/config, performance, testing |

---

## 1. Summary

`php2shell-tui` has two jobs:

1. **Detection (default, no POST):** answer whether a target runs an affected PHP build and whether the known PHP2Shell chain's preconditions are present. One consolidated exposure finding, plus the existing version finding.
2. **Verification (`--verify`):** execute the real, multi-stage PHP2Shell chain against a target whose build matches one of the five publicly calibrated profiles. Critical is emitted only after a unique proof marker is fetched. No canary, no arming probe, no scenario where a failed attempt is reported as safe.

The current pure chain is correct only for PHP 8.4.26 amd64. The other 13 shipped profiles reuse 8.4.26's heap calibration and cannot work. Guess mode fires wrong payloads, ignores the target's detected version/SAPI, and is expensive. This design removes guess mode and replaces the pure chain with the parametric upstream chain that the five verified profiles are calibrated for.

## 2. Context and problem

### 2.1 What the Go project contributes

`php2shell-scanner` is a detector, not an exploit. It contributes the checking layer:

- version assessment and EOL/patched states;
- phpinfo discovery and ini parsing;
- SAPI detection (mod_php vs FPM);
- exploit-precondition findings (`session.upload_progress`, `memory_limit`, `use_only_cookies`, etc.);
- a benign arming probe (not adopted: this project does not need a canary or an arming POST).

### 2.2 What the PHP project actually does

The current exploit is a native PHP port of 9bie's **pure HTTP** chain. Its A1/B1/A2/B2 builders, carrier, leak parser, offsets and stage constants are byte-for-byte correct for the one calibrated build: **PHP 8.4.26, amd64, official Apache image**. The previous lab confirmed RCE for that exact build.

The wrapper around it is not correct:

1. **Uncalibrated profiles.** 13 of 14 shipped profiles reuse 8.4.26's heap/stage parameters with only the symbol offsets changed. Upstream devploit states that stage parameters are per-build and a profile is only `rce: true` after a real proof. Guess mode runs those unverified profiles with `allowUnverified: true`.
2. **No version/SAPI match.** Guess mode does not compare the target's detected PHP version, architecture or SAPI to the profile. It can fire an 8.4.26 payload at 8.5.11, and a mod_php payload at FPM.
3. **amd64-only leak parser.** The pointer range and delta range are hard-coded for amd64. Every aarch64 profile fails its own delta check.
4. **No phpinfo/config detection.** The default scan cannot answer "probably exploitable"; it only reports the version.
5. **Cost.** Each guess attempt pins `workers - 1` connections and uploads tens of megabytes, repeated up to `max_attempts`. Most attempts cannot work.
6. **Coverage gap.** There is no 8.4.26 aarch64 profile, yet that is a real build.

### 2.3 Upstream facts used

- The only public chain with per-build parameters is the parametric chain (9bie archive/de0): `stage1_n`, `stage1_forge_len`, `stage2_t`, `stage2_v`, `stage3_pads`, `stage3_carrier`, `htdata`.
- devploit publishes five profiles with `verified: true` and `rce: true`:
  - PHP 8.4.25 aarch64
  - PHP 8.4.26 amd64
  - PHP 8.5.10 aarch64
  - PHP 8.5.11 aarch64
  - PHP 8.5.11 amd64
- PHP 7.4/8.0/8.1/8.2/8.3 have symbol offsets in some upstream inventories but no calibrated stage parameters and no verified RCE. They remain detection-only.

## 3. Goals and non-goals

### Goals

- **G1** — Default scan detects affected versions across all PHP versions and architectures, with one exposure finding that states SAPI, phpinfo data and chain preconditions.
- **G2** — `--verify` executes the real chain, all stages, against a target whose exact build matches a calibrated profile. Critical only on a unique proof marker.
- **G3** — Select a profile by exact PHP version and architecture, with CLI/config overrides. Fail fast, with a clear reason, when no calibrated profile exists.
- **G4** — Remove guess mode, uncalibrated profiles and the pure chain.
- **G5** — Reduce default scan cost to zero extra requests and remove wrong-profile attempts. `--verify` is a bounded, single-profile exploit.
- **G6** — Every default-scan claim is evidence-based; no POST without `--verify`.
- **G7** — The suite is green; the built PHAR is tested against a real lab matrix before release.

### Non-goals

- Exploiting PHP 7.4/8.0/8.1/8.2/8.3 without a calibrated profile. They are detected, not exploited.
- A canary endpoint or a benign arming probe. The tool is direct: detection by version/config, verification by real execution.
- Arbitrary command execution. The only command is `echo <unique marker>><proof file>`.
- Local-host or SSH scanning modes from the Go project.
- A new architecture, framework, dependency container or report format.
- Lab fixtures, Docker files or generated payloads in git.

## 4. Design

### 4.1 Detection layer (default)

#### 4.1.1 `PhpFingerprint`

A shared value object, created from the responses the engine already fetches. It never sends a request.

```php
final class PhpFingerprint
{
    /** @param array<string, ResponseInterface> $responses */
    public static function fromResponses(array $responses): self;

    /** @return list<array{version: string, source: string, confidence: string}> */
    public function versions(): array;

    /** @return null|array{url: string, ini: array<string, string>, sapi: ?string} */
    public function phpinfo(): ?array;

    public function sapi(): ?string;          // exact or "inferred: mod_php" / "inferred: fpm"
    public function serverOs(): ?string;      // debian, ubuntu, alpine, ... from the Server header
    public function hasPhpSignal(): bool;
    /** @return array<string, string> */
    public function ini(): array;
    /** @return list<string> */
    public static function paths(): array;
}
```

- `paths()` returns `['/', '/phpinfo.php', '/info.php']`.
- Version sources: `X-Powered-By` (high), `Server` (medium), phpinfo `PHP Version` (medium), body `PHP Version x.y.z` / `PHP/x.y.z` (low).
- phpinfo parsing: rows of `<td class="e">name</td><td class="v">value</td>`; strip tags, HTML-decode, lowercase the name, trim the value. Also parse `PHP Version` into `php version`.
- SAPI: exact phpinfo `Server API`, else infer `mod_php` from Apache + PHP headers, `fpm` from nginx + PHP headers. Inferred values are labelled. An inferred `mod_php` is reported as unknown, not as proof of mod_php: Apache can front FPM with the same headers.
- `serverOs()` normalizes the `Server` header OS token; `hasPhpSignal()` uses the existing `PhpDetection::signals()` on the baseline.
- The response body is rewound before and after reading.

`PhpVersion` uses `PhpFingerprint::versions()` and keeps its existing worst-version logic. It additionally scans the baseline body, so a page that calls `phpinfo()` or leaks its version in HTML is detected without extra requests.

#### 4.1.2 `php2shell-exposure` finding

`Php2Shell::paths()` returns `PhpFingerprint::paths()`; the existing `php_version` and `sensitive_files` checks already request these paths, so the default scan adds zero requests. If those checks are disabled, `php2shell` adds at most two GETs.

The check always emits one `php2shell-exposure` finding (even without `--verify`). It does not send a POST.

Evidence checklist:

- detected version and source;
- SAPI and whether it is exact or inferred;
- `session.upload_progress.enabled`;
- `session.use_strict_mode`;
- `session.use_only_cookies`;
- `session.serialize_handler`;
- `memory_limit`;
- `post_max_size`;
- `upload_max_filesize`;
- `display_errors`;
- `open_basedir` / `disable_functions` (reported, not gated);
- `phpinfo` URL, if any;
- the matching calibrated profile, if one exists.

Severity:

| State | Severity | Meaning |
|---|---|---|
| version affected, all observables met or unknown | **High** | chain preconditions present or not disproved; `--verify` is the next step |
| version affected, a known precondition is closed | **Medium** | affected by version, but the public chain cannot run as-is (FPM, upload progress off, display errors off, unlimited memory, body limit too small, strict mode on) |
| version unknown | **High** | PHP present but build cannot be judged; pass `--php-version` |
| version patched | **Info** | not applicable |
| no PHP signal | **Info** | no claim |

The `php_version` finding remains Critical for an affected advertised version (per the advisory). The exposure finding is not a second Critical; it answers whether the known chain can actually run.

#### 4.1.3 No POST by default

- No canary, no arming probe, no heuristic multipart POST.
- `--verify` is the only path that sends a POST or opens a raw socket.
- No separate confirmation prompt: `--verify` itself is the authorization; the help, README and TUI warnings carry the risk notice.

### 4.2 Verification layer (`--verify`)

#### 4.2.1 Why the parametric chain

The five verified profiles are calibrated for the parametric upstream chain, not the pure chain. The pure chain is deleted. Class boundaries stay: `PayloadBuilder` builds bodies, `Php2ShellPoc` orchestrates, `Profile` is data, `RawHttp` is transport, `CookieLeakParser` parses leaks.

#### 4.2.2 Stage flow

All requests are real, in this order:

1. **Pin workers** — hold `workers - 1` incomplete POSTs; leave one prefork child free. `workers = 1` skips pinning and is for a single-worker lab.
2. **Rotate** — abort the current worker over HTTP; prefork replaces it.
3. **Stage 1** — send the OOM prelude, then the leak request with `stage1_n` 48-byte fields and a `stage1_forge_len` forge. Parse `Set-Cookie: PHPSESSID=`; the 2 MB-aligned mode of the decoded heap pointers is the Zend MM chunk base. Retry up to `retries` times, rotating between failures.
4. **Rotate**.
5. **Stage 2** — send the prelude, then the leak request with 983 fields; field index `stage2_t` gets 16 values of length `stage2_v`. The pointer at cookie offset 8 is `zval_ptr_dtor`; subtract the profile offset and require a 4 KB-aligned `libphp` base. Retry up to `retries` times.
6. **Rotate**.
7. **Stage 3** — send the pad request (`stage3_pads`, plus `Cookie: PHPSESSID=` + 32 `a` for the bookworm profiles), then the trigger:
   - `htdata = chunk + profile.libphp.htdata`;
   - `zif = libphp + profile.libphp.zif_system`;
   - fake `zend_array` with `pDestructor = zif_system`;
   - `stage3_carrier: true` profiles use the 15-byte carrier at `PS(http_session_vars)`; the alternative 55-byte fake reference is not shipped but kept in the builder for lab profiles.
   - command: `echo <7-char marker>><1-char file>` — exactly 14 bytes, the carrier's maximum.
8. **Proof** — after each stage-3 attempt, sleep 0.8 s and fetch the candidate proof paths with a cache-busting query. Success requires HTTP 200 and `trim(body) === marker`. Stage 3 retries up to `retries + 2` times, rotating between failures.
9. **Failure** — Info finding with the last reason ("no chunk base", "no libphp base", "proof not retrievable"). Never "safe".

#### 4.2.3 Worker pinning

- `poc.workers` is the target's prefork `MaxRequestWorkers`. It is required for `--verify`; the example config sets 150 (official image), a single-worker lab sets 1.
- If `poc.workers` is absent, no payload is sent; Info explains how to set it.
- Pinning uses `RawHttp::openIncompletePost()`: `workers - 1` half-open `application/x-www-form-urlencoded` POSTs. The local FD budget is checked with `posix_getrlimit()` when available.
- `poc.max_workers` (default 200) refuses a profile/worker count above the cap.

#### 4.2.4 Memory limit and body limits

The chain needs a finite `memory_limit` and an OOM field larger than it.

- Source order: `poc.memory_limit` config/`--memory-limit` CLI, then phpinfo `memory_limit`.
- If unknown, probe with URL-encoded bodies of 16, 64 and 256 MiB and parse `Allowed memory size of (\d+) bytes` from the response. The probe is a POST, only under `--verify`.
- If the probe fails, use `profile.oom_mb` (12) and warn; the attempt may fail, and no false positive is possible.
- `huge_mb = (limit == 8 && profile.oom_mb > 0) ? profile.oom_mb : limit + profile.oom_margin_mb` (default margin 12).
- Gate: if `memory_limit` is `-1`, do not attempt (no OOM).
- Gate: if `post_max_size` is known and `0 < post_max_size <= huge_mb`, do not attempt. The same `huge_mb` helper is used by the exposure finding and the gate; a missing or unreadable `memory_limit` is unknown, not closed.
- `upload_max_filesize` is reported but is not a gate: the large value is a plain form field, not a file.

#### 4.2.5 Target gates

Before a single payload byte is sent, all of these must pass:

| Gate | Behaviour when known | Behaviour when unknown |
|---|---|---|
| exact version profile | required; no profile → Info | use `--php-version` |
| architecture | required if the version has multiple profiles; else use the only one | `--arch` |
| SAPI | FPM/other → Info, no attempt | allow |
| `session.upload_progress.enabled` | Off → Info, no attempt | allow |
| `display_errors` | Off → Info, no attempt (the parametric chain's leaks need it) | allow |
| `session.use_strict_mode` | 1 → Info, no attempt (body-supplied session id is rejected) | allow |
| `memory_limit` | `-1` → Info, no attempt | probe |
| `post_max_size` | too small for `huge_mb` → Info, no attempt | allow |
| OS/distro in `Server` | mismatch with the Debian profiles → Info, no attempt | allow |
| `poc.workers` | absent → Info, no attempt | — |

Each refused attempt produces one `php2shell-poc-inconclusive` Info finding with the exact reason. No socket is opened for a refused attempt.

#### 4.2.6 Proof and cleanup

- A 1-character `[a-z0-9]` proof file; both `<post_path dir>/<file>` and `/<file>` are pre-checked as 404, with up to five random names.
- The command writes the file relative to the PHP process working directory. If the scanner cannot fetch it from either candidate, the result is "proof not retrievable", not success.
- The finding reports the actual proof URL and instructs the operator to delete the proof file.
- No arbitrary command, no staged script, no persistence.

### 4.3 Data model

#### 4.3.1 Profile schema

Adopt the devploit profile schema verbatim:

```json
{
  "name": "php-8.4.26-bookworm-amd64",
  "php_version": "8.4.26",
  "branch": "8.4",
  "fixed_in": "8.4.27",
  "sapi": "apache2handler",
  "arch": "amd64",
  "distro": "debian",
  "verified": true,
  "rce": true,
  "upstream_profile": "bookworm",
  "libphp": {
    "zif_system": "0x465370",
    "zval_ptr_dtor": "0x65eb60",
    "htdata": "0x690d8"
  },
  "stages": {
    "stage1_n": 841,
    "stage1_forge_len": 79,
    "stage2_t": 406,
    "stage2_v": 16,
    "stage3_pads": [[31,31],[31,31],[31,31],[31,31],[31,31],[31,31]],
    "stage3_carrier": true
  },
  "config": {
    "memory_limit": 8388608,
    "display_errors": "On",
    "session_upload_progress": "On",
    "workers": 1
  },
  "oom_mb": 12,
  "oom_margin_mb": 12,
  "memory_limit_tested_mb": [8, 128],
  "status": "RCE verified at 8M and 128M (huge_mb = limit + 12)",
  "source": "https://github.com/devploit/php2shell (MIT)"
}
```

Only `verified: true` **and** `rce: true` profiles are selectable. Missing/ill-typed fields are a profile error, not a silent default.

Five files:

| id | version | arch | zif_system | zval_ptr_dtor | htdata | forge |
|---|---|---|---|---|---|---|
| `php-8.4.25-bookworm-aarch64` | 8.4.25 | aarch64 | `0x42fa30` | `0x637ae0` | `0x690d8` | 63 |
| `php-8.4.26-bookworm-amd64` | 8.4.26 | amd64 | `0x465370` | `0x65eb60` | `0x690d8` | 79 |
| `php-8.5.10-bookworm-aarch64` | 8.5.10 | aarch64 | `0x52e130` | `0x75d360` | `0x690d8` | 63 |
| `php-8.5.11-bookworm-aarch64` | 8.5.11 | aarch64 | `0x5314f0` | `0x761b80` | `0x690d8` | 63 |
| `php-8.5.11-bookworm-amd64` | 8.5.11 | amd64 | `0x5996e0` | `0x7b47a0` | `0x690d8` | 63 |

All five use `stage1_n: 841`, `stage2_t: 406`, `stage2_v: 16`, `stage3_pads: [[31,31] x 6]`, `stage3_carrier: true`, `oom_mb: 12`, `oom_margin_mb: 12`.

#### 4.3.2 `ProfileCatalog`

```php
final class ProfileCatalog
{
    public function __construct(string $directory);
    /** @return list<Profile> */
    public function all(): array;
    /**
     * @return array{profile: ?Profile, reason: string}
     */
    public function select(?string $version, ?string $arch, ?string $profile, ?string $serverOs): array;
}
```

- Exact version match only. A branch input (`8.5`) is rejected with "specify an exact patch release" and the available versions.
- If the exact version has multiple arches, `--arch` is required.
- `--profile`/`poc_profile` is an explicit id or path and bypasses auto-selection, but the profile must still be verified/rce and must match the detected version and OS when those are known.
- Auto-selection uses only trusted version sources (`X-Powered-By`, phpinfo, `Server`); the low-confidence body version is never sufficient to fire the chain. If trusted sources disagree, verification is refused until the operator resolves the conflict with an unambiguous target, `--php-version`, or an explicit profile.
- `--php-version` is an override for a target with no trusted version, not a way to override a contradictory advertised version. A trusted version that differs from the override is refused.
- `Server` OS matching: `Debian`/`bookworm` → `debian`; `Ubuntu` → `ubuntu`; `Alpine` → `alpine`. A known mismatch refuses.
- Unverified profiles are never selected, even by an explicit path.

#### 4.3.3 `PocPlan`

Replaces `GuessPlan`:

```php
final class PocPlan
{
    public function __construct(
        public readonly ?string $profile = null,
        public readonly ?string $version = null,
        public readonly ?string $arch = null,
        public readonly ?int $workers = null,
        public readonly ?int $memoryLimitMb = null,
        public readonly int $timeout = 300,
        public readonly int $requestTimeout = 90,
        public readonly int $retries = 3,
        public readonly int $maxWorkers = 200,
    );
    public function withMemoryLimit(int $memoryLimitMb): self;
}
```

- `workers` null means "not configured": `--verify` refuses before sending.
- `memoryLimitMb` null means "read phpinfo or probe".
- Validation: workers >= 1, memoryLimitMb >= 1 when set, timeouts >= 1, retries >= 1, maxWorkers >= workers.

#### 4.3.4 `PocResult`

```php
final class PocResult
{
    public function __construct(
        public readonly bool $confirmed,
        public readonly string $reason,
        public readonly ?string $proof = null,
        public readonly ?string $evidence = null,
        public readonly ?string $proofPath = null,
    ) {}
}
```

`terminal` is removed: there is one profile and no guess loop.

### 4.4 CLI and config

New `scan` options:

```
--verify
--php-version <x.y.z>    exact PHP patch version; overrides detection
--arch <amd64|aarch64>
--profile <id|path>      explicit calibrated profile
--workers <n>            target prefork MaxRequestWorkers (required for verify)
--memory-limit <MiB>     target memory_limit when phpinfo hides it
```

Precedence: `--profile` > target `poc_profile` > auto by version/arch. `--php-version`/`--arch` affect auto-selection; an explicit profile wins but a detected version/OS mismatch is still refused.

Config:

```yaml
poc:
  workers: 150          # target prefork count; 1 for a single-worker lab
  memory_limit: 128     # optional MiB; otherwise phpinfo or probe
  timeout: 300          # overall seconds
  request_timeout: 90   # per raw request
  retries: 3            # stage1/stage2; stage3 uses retries + 2
  max_workers: 200
  profile: ""           # optional id/path
```

Removed from config and code: `poc.guess`, `poc.profiles`, `poc.arch`, `poc.max_attempts`, `poc.total_timeout`, `GuessPlan`. Old keys are ignored (pre-release config), and the README documents the migration.

Target `post_path` remains; it selects the endpoint and the proof candidates. Target `poc_profile` remains as an explicit override.

### 4.5 File structure

Final structure:

```
src/PhpFingerprint.php                     new   shared detection value object
src/Check/PhpVersion.php                   edit  use PhpFingerprint
src/Check/Php2Shell.php                    edit  exposure + verify wiring
src/Config.php                             edit  simplified poc config
src/Command/ScanCommand.php                edit  new CLI options
src/Poc/Profile.php                        edit  devploit schema
src/Poc/ProfileCatalog.php                 new   profile selection
src/Poc/PocPlan.php                        new   replaces GuessPlan
src/Poc/PayloadBuilder.php                 edit  parametric chain bodies
src/Poc/CookieLeakParser.php               new   replaces LeakParser
src/Poc/Php2ShellPoc.php                   edit  parametric chain orchestration
src/Poc/PocResult.php                      edit  remove terminal
src/Poc/ProofPath.php                      keep  1-char proof names
src/Poc/RawHttp.php                        edit  Content-Length + concurrent read
src/Data/poc/*.json                        replace  five verified profiles
src/Data/repro/php2shell-exposure.md       new   reproduce steps
php2shell-tui.yaml                         edit  simplified poc block
README.md                                  edit  detection/verification contract
```

Deleted:

```
src/Poc/GuessPlan.php
src/Poc/LeakParser.php
src/Data/poc/php-7.4.33-...json
src/Data/poc/php-8.0.30-...json
src/Data/poc/php-8.1.34-...json
src/Data/poc/php-8.2.0-...json
src/Data/poc/php-8.2.34-...json
src/Data/poc/php-8.3.0-...json
src/Data/poc/php-8.3.33-...json
src/Data/poc/php-8.3.35-...json
src/Data/poc/php-8.4.25-...aarch64.json (replaced)
src/Data/poc/php-8.5.0-...json
src/Data/poc/php-8.5.10-...json (replaced)
src/Data/poc/php-8.5.11-...json (replaced)
```

`src/Data/php-affected.json` and `PhpVersionDb` stay.

### 4.6 Error handling and safety

- A failed stage returns Info with the last reason; no "safe" claim.
- A proof is accepted only on HTTP 200 and exact marker equality after trim.
- Pre-existing proof paths are avoided (404 pre-check, five attempts).
- The chain writes one file and executes only `echo <marker>><file>`; no arbitrary command surface.
- `--verify` is the explicit authorization; the tool still warns in help/README about worker pinning, large bodies, worker crashes and the proof file.
- The default scan never opens a raw socket and never sends a POST.
- Profiles are local JSON; a profile path is never a URL.
- `poc.workers` is required for a real attempt; no blind 149-connection pinning.
- The total deadline and per-request timeout are enforced; the pinning sockets and temp files are closed/deleted in `finally`.
- `--verify` without a calibrated profile, or against a patched/FPM/closed target, sends zero payload bytes.

### 4.7 Performance

- Default scan: same three paths as today; phpinfo parsing adds no requests. No POST.
- No guess loop: at most one profile per target.
- Profile selection is a directory scan of five files, cached per run.
- `--verify` is gated before any payload; patched, FPM, no-profile and closed-precondition targets cost zero payload.
- The parametric chain is inherently heavy (12 MB preludes, worker rotation). It is an exploit, not a scan. `retries` and `timeout` are configurable; the default is one profile, not a list.
- The old 14-profile loop, `max_attempts`, `total_timeout`, `GuessPlan` and the 13 fake profiles are removed.
- Detection requests are sent with `Connection: close`. A keep-alive GET would hold a prefork child and, on a two-worker target, leave the verification chain queued behind the scanner itself. The lab found this on the 2-worker test.
- The profile catalog lists its directory with `scandir()`, not `glob()`, so the same five profiles load from the built PHAR (`glob()` does not read `phar://`).
- SAPI matching accepts the real phpinfo value `Apache 2 Handler` as well as `Apache 2.0 Handler` and `apache2handler`; the lab found the apostrophe-free form on PHP 8.4/8.5.

### 4.8 Testing

#### Unit (no network)

- `PhpFingerprintTest` — versions from each source; phpinfo rows/ini/SAPI; baseline body; no stream consumption; SAPI inference.
- `PhpVersionTest` — existing matrix plus baseline body detection.
- `Php2ShellTest` — exposure severity matrix; no POST without verify; exact version/arch selection; branch rejection; no profile; FPM; upload progress off; display errors off; strict mode on; unlimited memory; small `post_max_size`; missing workers; distro mismatch; proof success/failure; never "safe".
- `ProfileTest` — five files load; required fields; hex parsing; `verified`+`rce`; pads; invalid profile.
- `ProfileCatalogTest` — exact/branch/arch/explicit/OS; no match; multiple arches; unverified refusal.
- `PocPlanTest` — validation and `withMemoryLimit`.
- `PayloadBuilderTest` — golden hashes for rotate A/B, stage1 A/B, stage2 A/B, stage3 A/B, fake ht/carrier; compare to the Python oracle; small `huge_mb` for unit speed.
- `CookieLeakParserTest` — 2 MB chunk mode (count >= 8), libphp 4 KB alignment, amd64/aarch64 pointers, invalid input.
- `RawHttpTest` — local socket fixture; Content-Length multipart; 1xx; response cap; concurrent read when the server responds before reading the full body; cleanup.
- `ProofPathTest` — 1-char names, candidates, pre-existing path avoidance.
- `ConfigTest` / `ScanCommandTest` — new options; old keys ignored; no POST without verify; CLI version/arch/workers/memory; PHAR/source parity is manual.

#### Real lab matrix (release gate, not committed)

- Five builds: 8.4.25 aarch64, 8.4.26 amd64, 8.5.10 aarch64, 8.5.11 aarch64, 8.5.11 amd64.
- Official `php:<version>-apache` images; `display_errors=On`, `memory_limit=8M` (and 128M for 8.4.26), `post_max_size=64M` for the 8M tests and `256M` for the 128M test, `upload_max_filesize=64M`, `session.upload_progress.enabled=On`, `session.use_strict_mode=0`, `session.use_cookies=1`; single-worker for the match test and 2/4-worker pinning for the pin test.
- Negative: patched 8.4.27/8.5.12; observed FPM; `display_errors=Off`; `post_max_size=8M`; 7.4.33 fail-fast; contradictory `--php-version`; pre-existing proof file; wrong marker.
- Hidden version: keep the calibrated build (`expose_php=On`) and strip `X-Powered-By` at the edge; the target has no version in headers, body, or phpinfo, and `--verify --php-version 8.4.26 --arch amd64` proves RCE. A genuinely `expose_php=Off` build changes the heap calibration and may not produce a retrievable proof; that limitation is reported, not hidden.
- Default scan on every lab: exposure finding, zero POSTs (access log), no RCE finding.
- `--verify` on each of the five: real marker, one profile, Critical.
- Built PHAR, not just source.
- Compare detection with the Go scanner on the same targets.
- No lab files, Docker data, reports or generated payloads in git.

## 5. Acceptance criteria

1. `composer test` is green.
2. Default scan sends no POST to any target and emits exactly one `php2shell-exposure` finding per target plus the existing version finding.
3. `--verify` on each of the five calibrated builds produces `php2shell-rce` Critical with the unique marker fetched from the proof URL.
4. `--verify` against patched, FPM, `display_errors=Off`, `post_max_size` too small, unlimited memory, strict mode 1, unknown/no profile, branch input, missing workers, or a distro mismatch produces an Info finding and sends zero payload bytes.
5. No uncalibrated profile is ever selected; `GuessPlan`, `LeakParser`, the pure builder and the 13 fake profiles are gone.
6. The built `php2shell-tui` PHAR passes the same release checks.
7. The branch contains no lab/Docker/report artifacts.

## 6. Decisions

| Decision | Rationale |
|---|---|
| Parametric chain over the pure chain | Only the parametric chain has per-build stage calibration for the five verified profiles. |
| Five profiles only | Upstream verified/rce data; everything else is detection-only. |
| Exact version + arch selection | Offsets and heap layout are per-build; a branch is not a build. |
| Fail fast, no forced attempt | A wrong payload can crash workers and cannot prove anything. |
| One exposure finding | Keeps the report readable while carrying the full precondition checklist. |
| No canary/arming probe | The user's contract: direct detection, real execution under `--verify`. |
| Require `poc.workers` | Prevents blind 149-connection pinning of an unknown target. |
| Memory limit from phpinfo/probe | The OOM field must exceed the real limit; a fixed 12 MB breaks at 128M. |
| 14-byte proof command | Fits the 167-byte carrier; only the marker is executed. |
| Remove guess mode | It is the direct cause of wrong-profile payloads and cost. |

## 7. Risks and limitations

- **Proof path depends on CWD.** The command writes a relative file; if the PHP working directory is not the script directory or webroot, RCE may succeed but the proof is not retrievable. Reported as Info "proof not retrievable", never Critical.
- **Target configuration.** The parametric chain needs `display_errors=On`, finite `memory_limit`, `post_max_size` above the OOM field size (`oom_mb` at 8M, otherwise `memory_limit + 12`), `session.upload_progress=On`, `use_strict_mode=0`, and a prefork worker count the operator knows. These are gates/checks, not assumptions.
- **Hidden versions.** `expose_php=Off` changes the calibrated heap layout; the chain can run and still fail to produce a retrievable proof. Stripping `X-Powered-By` at the edge keeps the build match and lets the override prove RCE. A trusted version that contradicts the override is refused.
- **Intrusiveness.** Worker rotation, half-open pinning and 12 MB bodies can disrupt the target. `--verify` is explicit and the README must say so.
- **Build matching.** Version + arch + Server OS is not a binary fingerprint. A same-version different build may fail; the marker prevents false positives but still costs an attempt. A wrong build can crash a worker.
- **HTTPS.** The transport supports verified TLS, but the lab matrix is HTTP; HTTPS is not lab-verified. The proof marker still prevents false positives.
- **Coverage.** 7.4–8.3 are affected but not exploitable by this tool; detection still reports them. More profiles require calibration on a replica and a real proof.
- **Upstream licensing.** The profiles are MIT (devploit); the chain is a native implementation from public research. Attribution is kept in the profile `source` and README.

## 8. Open items

- HTTPS lab verification (optional, before claiming HTTPS exploit support).
- Additional calibrated profiles (8.3.35, 8.4.26 aarch64) only after a real proof; not in this scope.
- A future `php2shell_assess`-style leak-only mode is out of scope.

## Appendix A — CLI examples

```bash
# detection only, no POST
bin/php2shell-tui scan --config target.yaml --no-tui --format json

# real chain, exact build; workers = target MaxRequestWorkers
bin/php2shell-tui scan --config target.yaml --no-tui --format json --verify \
  --php-version 8.4.26 --arch amd64 --workers 150

# target hides the version but the operator knows the build
bin/php2shell-tui scan --config target.yaml --no-tui --format json --verify \
  --profile php-8.5.11-bookworm-aarch64 --workers 150 --memory-limit 128

# affected but no calibrated profile: Info, zero payload
bin/php2shell-tui scan --config target.yaml --no-tui --format json --verify \
  --php-version 7.4.33
```

## Appendix B — Sources

- 9bie/php2shell-bypass-aslr-exp — parametric chain (`archive/legacy-8m/exploit.py`).
- devploit/php2shell — MIT profiles, calibration guide, auto dispatcher.
- aancw/php2shell-scanner — detection model, phpinfo/SAPI/ini checks.
- PHP advisories of 2026-10-21 for the version matrix.
