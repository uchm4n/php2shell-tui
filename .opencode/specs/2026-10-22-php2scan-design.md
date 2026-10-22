# php2scan — Design Specification

| | |
|---|---|
| **Status** | Draft — awaiting review |
| **Date** | 2026-10-22 |
| **Supersedes** | — |
| **Covers** | `php2scan` v1.0 — multi-host exposure scanner for PHP2Shell (CVE-2026-109618 / CVE-2026-109619) and general web misconfiguration |

---

## 1. Summary

`php2scan` is a Composer-based PHP CLI that scans an **allowlisted set of hosts you control**, detects security exposure, verifies what can be verified safely, and emits a report in which every finding carries:

1. a one-sentence **"How to exploit"** line, and
2. an ordered list of **reproduce steps** — copy-pasteable commands you can run by hand.

The tool renders a live TUI (via `php-tui/php-tui`) while scanning multiple hosts concurrently, and falls back to plain text / JSON / Markdown when not attached to a TTY.

## 2. Goals

- **G1** — Answer one question authoritatively per host: *does this host serve PHP, at what version, and is that version exposed to PHP2Shell?*
- **G2** — Surface the common web exposures that matter in practice: leaked secrets, missing security headers, expiring TLS, stale CMS, stray webshells, unexpected open ports.
- **G3** — Every finding must be **reproducible by hand**: evidence + one-sentence exploit + concrete commands.
- **G4** — Multiple hosts scanned concurrently, live progress, results browsable in a TUI.
- **G5** — Configuration in a single file; wordlists and reproduce steps editable without touching PHP.
- **G6** — Safe by construction: allowlisted targets, read-only requests, verification opt-in.

## 3. Non-goals

- Not a general-purpose vulnerability scanner. It does not attempt to enumerate or fuzz an attack surface beyond a fixed, curated path list.
- Not a log-analysis tool — no access-log or EDR ingestion.
- **Does not exploit the memory-corruption CVEs.** PHP2Shell's proof-of-concept *is* a worker crash; shipping it inside a scanner would be a self-DoS against your own production. Exposure is determined by version, which is what the official advisory specifies. See §6.3.
- Not a CMS vulnerability database. Detected CMS versions are reported; mapping them to upstream CVEs is left to you (or a future phase).
- No dependency injection container, no ORM, no framework.

## 4. Context

PHP2Shell is a family of critical vulnerabilities in **core PHP**, disclosed 2026-10-21:

| CVE | Class | Impact |
|---|---|---|
| CVE-2026-109618 | Out-of-memory corruption | Pre-auth RCE as the PHP worker |
| CVE-2026-109619 | Stale global state across requests | Use-after-free → memory disclosure / RCE |

Affected branches and their first fixed releases:

| Branch | Vulnerable | First fixed |
|---|---|---|
| 8.2 | `< 8.2.35` | 8.2.35 |
| 8.3 | `< 8.3.36` | 8.3.36 |
| 8.4 | `< 8.4.27` | 8.4.27 |
| 8.5 | `< 8.5.12` | 8.5.12 |

Branches below 8.2 (5.x, 7.x, 8.0, 8.1) are end-of-life and have **no fix**. The advisory states affected releases reach back to PHP 5.4, and that application code being secure does not protect you — a "Hello World" on an affected runtime is vulnerable.

**This is why the tool exists.** Remote scanning cannot *prove* a PHP version when `X-Powered-By` is disabled, so the tool reports a **confidence level** and, when the version is unknown, tells you the exact command to run on the host to find out.

### 4.1 Workspace layout

Everything lives under the project root (`/Users/u/www/projects/php2shell`). Source layout is in §6.4; the workspace folders are:

```
specs/     design specifications (this document)
plans/     implementation plans
tmp/       scratch space: probes, fixtures, captured responses (gitignored)
.opencode/ opencode workspace data (agent notes, plan mirror)
```

## 5. Safety & authorization model

| Rule | Enforcement |
|---|---|
| Only hosts in `targets:` are ever contacted | `Config::targets()` is the sole source; no CLI target argument exists |
| Read-only requests | Phase 1 = `GET`/`HEAD` only. Phase 3 verification = `GET` only, no state-changing params |
| Politeness | Per-host concurrency cap, per-host inter-request delay, connect + read timeouts |
| Verification is opt-in | `--verify` required; `--verify` against a host without `staging: true` requires `--yes` |
| No memory-corruption payloads | PHP2Shell PoC is deliberately not implemented (§6.3) |
| Evidence retained | Every finding stores the request line, response status, byte size, and the matched pattern |
| Findings are reproducible by hand | Reproduce steps contain commands, never opaque payloads |

## 6. Architecture

### 6.1 Component flow

```
php2scan.yaml
     │
     ▼
  Config ──validates──▶ Target[]  (allowlist)
     │
     ▼
  Engine ──parallel (CurlMultiHandler)──▶ Check[] ──▶ Finding[]
     │                                              │
     │                                              ├─ severity
     │                                              ├─ evidence
     │                                              ├─ exploit  (1 sentence)
     │                                              └─ reproduce[] (commands)
     ▼
  Report ──▶ TUI  |  text  |  json  |  markdown
```

### 6.2 Concurrency model

`Http\Pool` wraps Guzzle's `CurlMultiHandler` and drives it manually:

- Requests are enqueued up to `options.concurrency`.
- The engine loop calls `$handler->tick()` on each iteration, then redraws the TUI.
- Promise callbacks resolve findings as responses land.
- A per-host timestamp map enforces `options.delay_ms` between requests to the *same* host.

This is required because a blocking `Guzzle::request()` loop would freeze the TUI and serialise hosts.

### 6.3 Why PHP2Shell is not exploited by the tool

The CVE-2026-109618 proof-of-concept triggers out-of-memory handling in the PHP worker. Running it against a live host kills the worker — a deliberate, self-inflicted denial of service on your own production, visible as 502s and a worker restart. The advisory itself frames exposure in terms of version, so:

- the tool **proves** the version (and its confidence),
- the report **names** the published technique in the one-sentence exploit line,
- the reproduce steps point at the published write-up and describe the observable effect.

A live test, if wanted, is run **by hand, outside this tool**, against one nominated host, on a staging copy first.

### 6.4 Source layout

```
composer.json
bin/php2scan
php2scan.yaml.example
src/
  Command/ScanCommand.php            CLI entry (symfony/console)
  Config.php                         config load + validation
  Target.php                         one allowlisted host
  Engine.php                         orchestrates targets x checks
  Finding.php                        severity + evidence + exploit + reproduce
  Severity.php                       enum: critical|high|medium|low|info
  PhpVersionDb.php                   affected-version matrix + triage
  Http/Client.php                    Guzzle wrapper (timeouts, redirects, no http_errors)
  Http/Pool.php                      curl-multi driver + tick loop
  Check/Check.php                    interface: id(), severity(), run()
  Check/PhpDetection.php             is PHP present?
  Check/PhpVersion.php               version + CVE triage
  Check/SensitiveFiles.php           leaked secrets / backup files
  Check/SecurityHeaders.php          OWASP header rulebook
  Check/Tls.php                      cert expiry / chain / hostname
  Check/AppFingerprint.php           CMS + framework identification
  Check/WebshellIndicators.php       webshell IOC paths
  Check/OpenPorts.php                unexpected listening ports
  Check/SqlInjection.php             phase 3 (opt-in)
  Check/ReflectedXss.php             phase 3 (opt-in)
  Check/LocalFileInclusion.php       phase 3 (opt-in)
  Report/Report.php                  one class, format switch
  Report/Theme.php                   severity → colour
  Ui/TuiRenderer.php                 php-tui rendering + key handling
  Ui/PlainRenderer.php               text output
  Crawler/Crawler.php                phase 3 — link/form/parameter discovery
  Data/Wordlists.php                 loads data/*.txt
  Data/Reproduce.php                 loads data/repro/*.md
data/
  sensitive-paths.txt
  webshell-paths.txt
  open-ports.txt
  php-affected.json
  repro/<finding-id>.md
tests/
  Unit/PhpVersionDbTest.php
  Unit/ConfigTest.php
  Unit/FindingTest.php
  Unit/ReportTest.php
  Integration/EngineTest.php
  Integration/FixtureServerTest.php
```

`Report` is a single class with a format switch rather than three classes; `../../data` holds all wordlists and reproduce steps so they are editable without touching PHP.

## 7. Configuration reference

`php2scan.yaml` (default path; override with `--config`):

```yaml
targets:
  - https://www.php2shell.com
  - url: https://legacy.example.com
    vhost: legacy.example.com        # override the Host: header while keeping the URL as
                                     # written — e.g. url https://203.0.113.10/ + Host:
                                     # legacy.example.com to reach a vhost on a shared IP
    paths: ["/wp-content/uploads"]   # extra directories for webshell probing
    staging: true                    # suppress the --yes prompt for --verify

checks:
  php_presence: true
  php_version: true
  sensitive_files: true
  security_headers: true
  tls: true
  app_fingerprint: true
  webshell_indicators: true
  open_ports: true
  injection: false                   # phase 3; requires --verify as well

options:
  concurrency: 8
  timeout: 10                        # seconds, per request
  connect_timeout: 5
  delay_ms: 100                      # per-host politeness delay
  user_agent: "php2scan/1.0 (+https://example.com/about)"
  verify: false                      # run safe proof-of-concept requests
  min_severity: medium               # below this severity: excluded from the text/markdown
                                     # report and from the exit code, but still shown in the
                                     # TUI and in JSON output

output:
  format: tui                        # tui | text | json | markdown
  report_dir: ./reports
```

Validation is fail-fast with actionable messages: unknown check name, malformed URL, missing `targets:`, unknown top-level key.

## 8. Check catalogue

### 8.1 Phase 1 — detection (always safe, read-only)

| id | What it does | Evidence captured |
|---|---|---|
| `php_presence` | `X-Powered-By`, `PHPSESSID` cookie, `Server: Apache/… PHP/8.x`, `Set-Cookie` patterns, body markers | which signal fired, on which URL |
| `php_version` | version extraction from the above + `phpinfo`/`info.php` probes | raw version string, source, confidence |
| `sensitive_files` | ~24 paths: `.env`, `.env.local`, `.git/config`, `.git/HEAD`, `../../composer.json`, `composer.lock`, `package.json`, `.htaccess`, `.DS_Store`, `phpinfo.php`, `info.php`, `server-status`, `server-info`, `wp-config.php.bak`, `backup.zip`, `dump.sql`, `.aws/credentials`, `id_rsa`, `.npmrc`, `.dockerignore`, `Dockerfile`, `adminer.php`, `phpmyadmin/`, `.well-known/security.txt` | status, size, matched secret pattern |
| `security_headers` | `aidantwoods/secureheaders` rulebook (missing/unsafe headers) + cookie flag audit (`Secure`, `HttpOnly`, `SameSite`) | which header, expected vs actual |
| `tls` | native `openssl_x509_parse` over a raw TLS socket: expiry, issuer, SAN match, TLS version | cert details, days remaining |
| `app_fingerprint` | WordPress, Drupal, Joomla, Laravel, Symfony, Next.js, PHPUnit — via body markers and known paths | product, version if leaked |
| `webshell_indicators` | IOC filenames (`shell.php`, `c99.php`, `r57.php`, `b374k.php`, …) plus configured upload dirs | path, status, content sniff |
| `open_ports` | native socket connect against `data/open-ports.txt` | port, service hint |

**Severity rules for the ambiguous cases** (fixed here so the implementation has no latitude):

| Case | Severity | Rule |
|---|---|---|
| `.env`, `.git/config`, `.aws/credentials`, `id_rsa`, `.npmrc` returned `200` | high | credential or repository disclosure |
| `../../composer.lock`, `composer.json`, `package.json` returned `200` | medium | dependency manifest disclosure |
| `phpinfo.php`, `info.php`, `server-status` returned `200` | medium | runtime information disclosure |
| `*.bak`, `backup.zip`, `dump.sql` returned `200` | high | source or database disclosure |
| `Dockerfile`, `.dockerignore` returned `200` | low | build metadata disclosure |
| Webshell IOC path returned `200` | high | only when the body also contains a shell primitive (`system(`, `shell_exec(`, `passthru(`, `proc_open(`, `base64_decode(` with `$_GET`/`$_POST`) — a bare `200` on `shell.php` is not enough |
| Port open and not `80`/`443` | medium | unless the port is `3306`, `5432`, `6379`, `27017`, `9200` → high (database/cache exposed) |
| Missing `Strict-Transport-Security` | medium | only for HTTPS targets |
| Missing `Content-Security-Policy` | low | |
| Missing `X-Content-Type-Options` | medium | |
| Missing `X-Frame-Options` and no CSP `frame-ancestors` | medium | |
| Cookie without `Secure` / `HttpOnly` / `SameSite` | medium | one finding per cookie per missing flag |

### 8.2 Phase 3 — verification (`--verify`, opt-in)

| id | PoC | Confirmed when |
|---|---|---|
| `sql_injection` | baseline vs `'` vs `' AND 1=2--` on discovered GET parameters | status/length/body diverges from baseline in the boolean sense |
| `reflected_xss` | unique marker appended to each GET parameter | marker echoed back unencoded |
| `local_file_inclusion` | `../../../../etc/passwd` on file-ish parameters | `root:x:0:0` pattern present in the response |

Phase 3 requires a crawler (`symfony/dom-crawler`) to discover parameters from the site's own links and forms, limited to `options.crawl_depth` (default 1) and the same host.

## 9. PHP2Shell triage

Input: a detected version string and its source.

```
version < 8.2                       → AFFECTED (EOL branch, no fix)     critical
8.2.x with x  < 8.2.35              → AFFECTED                            critical
8.3.x with x  < 8.3.36              → AFFECTED                            critical
8.4.x with x  < 8.4.27              → AFFECTED                            critical
8.5.x with x  < 8.5.12              → AFFECTED                            critical
version >= fixed release            → PATCHED                             info
version > newest known release      → UNKNOWN (re-check advisories)      low
PHP present, version undetermined   → UNKNOWN, verify on the host        high
no PHP detected                     → NOT AFFECTED                       info
```

**Confidence** in the detected version:

| Confidence | Source |
|---|---|
| high | `X-Powered-By: PHP/x.y.z` |
| medium | `Server: Apache/… PHP/x.y.z`, `phpinfo()` output |
| low | `PHPSESSID` cookie, body markers, `Content-Type` on a `.php` path |

A `low`-confidence version still drives the verdict, but the report states the confidence explicitly and always includes the on-host verification command (`php -v`) as the first reproduce step.

## 10. Finding model

```php
final class Finding {
    public string $id;            // 'php2shell-version', 'sensitive-file-env', …
    public string $title;         // 'PHP2Shell · CVE-2026-109618'
    public Severity $severity;    // critical|high|medium|low|info
    public string $target;        // host
    public string $evidence;      // 'HTTP 200, 1.2 KB, contains APP_KEY / DB_PASSWORD'
    public string $exploit;       // ONE sentence
    public array $reproduce;      // ordered list of steps (commands)
}
```

**Contract (enforced by test):** every finding has a non-empty `exploit` sentence and at least one non-empty reproduce step.

### 10.1 Severity scale

| Severity | Meaning |
|---|---|
| critical | Unauthenticated RCE or full credential compromise |
| high | Secret disclosure, exploitable injection, confirmed webshell |
| medium | Missing hardening, weak TLS, information leak |
| low | Cosmetic or defence-in-depth gap |
| info | Not affected / informational |

## 11. Reproduce steps

Stored as data, not code: `data/repro/<finding-id>.md`.

```
# blank line separates steps; lines starting with '#' are comments inside a step

curl -sS https://legacy.example.com/.env | head -20
# shows the raw file, including any APP_KEY / DB_PASSWORD lines
curl -sS https://legacy.example.com/.env | grep -iE 'APP_KEY|DB_PASSWORD|SECRET'
```

Every step is a runnable command with the real target substituted for `legacy.example.com`. **Substitution rule:** the steps use the target's URL exactly as written in `targets:`; for a `vhost` override the URL in the step is the origin URL and the `Host:` header is shown as an explicit `-H 'Host: …'` argument. The loader (`Data\Reproduce`) reads the file, splits on blank lines, and keeps comments attached to the preceding step.

For PHP2Shell the steps are deliberately **verification-oriented**, because the exploit itself is not shipped:

```
1  curl -sI https://legacy.example.com/ | grep -iE 'x-powered-by|server:'
2  ssh you@legacy.example.com 'php -v; php -i | grep -E "memory_limit|opcache.enable"'
3  # CVE-2026-109618 OOM trigger — the bytes are version- and build-specific.
   # Take them from the published research: https://www.wiz.io/blog/php2shell-php-rce
   # Expected effect: the FPM worker dies and the request returns 502.
   # Run this against a staging copy, never production.
```

## 12. Reporting

Four formats, one `Report` class:

- **`tui`** — live, browsable (§13). Default when stdout is a TTY.
- **`text`** — plain, grouped by target, one block per finding. Default when stdout is not a TTY.
- **`json`** — machine-readable; `{"targets": [...], "findings": [...], "summary": {...}}`.
- **`markdown`** — for pasting into a ticket.

Finding block (text format):

```
! CRITICAL  PHP2Shell · CVE-2026-109618 — legacy.example.com
    PHP 8.1.29 detected via X-Powered-By (confidence: high); affected — patched in 8.2.35.
    How to exploit: send the published OOM trigger to any .php endpoint to get pre-auth RCE as the FPM worker.
    Fix: upgrade PHP to >= 8.2.35 and restart the Apache/FPM workers.
```

Reports are also written to `output.report_dir` as `php2scan-YYYYMMDD-HHMMSS.<ext>`.

**Exit codes:** `0` no findings at or above `min_severity` · `1` findings present · `2` configuration or runtime error.

## 13. TUI

Two-pane vertical layout, produced with `GridWidget` (vertical direction, `Constraint::length(6)` header + `Constraint::min(0)` body):

```
┌ PHP2Shell Scan ────────────────────── 12/40 targets · 3m 41s ─┐
│ ● www.php2shell.com      done       0 findings                    │
│ ● legacy.example.com    done       2 findings   1 CRITICAL       │
│ ◐ old.example.org        scanning   ███████░░░  4/9 checks         │
└───────────────────────────────────────────────────────────────────┘
┌ Findings ───────────────────────────────────────────────────────┐
│ ▸ CRITICAL  PHP2Shell · CVE-2026-109618 — legacy.example.com     │
│   PHP 8.1.29 via X-Powered-By (high) · affected, patch >= 8.2.35  │
│   How to exploit: send the published OOM trigger to any .php      │
│   endpoint to get pre-auth RCE as the FPM worker.                │
│   HIGH  Exposed .env — legacy.example.com                       │
│   HTTP 200 · 1.2 KB · APP_KEY, DB_PASSWORD                       │
│   How to exploit: curl https://legacy.example.com/.env           │
└───────────────────────────────────────────────────────────────────┘
 ↑↓/jk scroll   enter/r expand   q quit   s save   f filter
```

Selecting a finding (`enter` / `r` to expand all) replaces the detail pane with the reproduce steps:

```
┌ Reproduce — PHP2Shell · CVE-2026-109618 ────────────────────────┐
│ 1  curl -sI https://legacy.example.com/ | grep -iE 'x-powered-by|server:' │
│ 2  ssh you@legacy.example.com 'php -v; php -i | grep -E "memory_limit"'  │
│ 3  # CVE-2026-109618 OOM trigger — bytes are version-specific;         │
│    # see https://www.wiz.io/blog/php2shell-php-rce                     │
│    # expected: FPM worker dies, request returns 502                    │
└────────────────────────────────────────────────────────────────────┘
```

Key handling uses `Terminal::events()->next()`, which is non-blocking (`StreamReader` sets STDIN non-blocking). `q` aborts the scan and still renders what has completed. `Ctrl-C` restores the terminal via a shutdown handler.

**TTY gate:** the TUI is used only when `stream_isatty(STDOUT)` is true; otherwise `text` is used. `--format` always overrides. `--no-tui` forces `text`.

**Known trap:** `Display::draw()` renders *and* flushes. Calling `Display::flush()` afterwards diffs against a swapped buffer and blanks the screen. Never call `flush()` separately.

## 14. Dependencies

| Package | Constraint | Role |
|---|---|---|
| `php-tui/php-tui` | `^0.2.1` | TUI widgets, display, viewport |
| `php-tui/term` | `^0.3` | terminal, key events, raw mode (pulled in by php-tui) |
| `guzzlehttp/guzzle` | `^8.3` | HTTP client, `CurlMultiHandler` |
| `symfony/console` | `^7.0` | CLI parsing, output |
| `symfony/yaml` | `^7.0` | config file |
| `symfony/dom-crawler` | `^7.0` | phase 3 — link/form/parameter discovery |
| `aidantwoods/secureheaders` | `^2.0.1` | OWASP header rulebook (`Psr7Adapter` + safe mode) |
| `phpunit/phpunit` | `^11` | dev only |

Runtime floor: **PHP ≥ 8.2** (matches the oldest branch we triage). Verified locally on PHP 8.5.12 / Composer 2.10.3.

`aidantwoods/secureheaders` is unmaintained since 2017; it is used only as the header *rulebook* (`Psr7Adapter` + safe mode, errors captured via a custom error handler). If its error-collection API proves unusable in practice, the fallback is a local 40-line table — equivalent effort, and called out in the task for that check.

## 15. Testing strategy

**Unit**

- `PhpVersionDbTest` — the full triage matrix: 8.1.29 → affected; 8.2.35 → patched; 8.2.34 → affected; 8.3.36 → patched; 8.4.27 → patched; 8.5.11 → affected; 8.5.12 → patched; 5.6.40 → affected (EOL); unknown → high/verify; no PHP → info.
- `ConfigTest` — valid config parses; unknown check name rejected; malformed URL rejected; empty `targets` rejected; per-target overrides applied.
- `FindingTest` — every produced finding has a non-empty exploit sentence and ≥1 reproduce step (contract).
- `ReportTest` — all four renderers produce output containing the target, severity, exploit line and reproduce steps; `json` output is valid JSON.

**Integration** — a fixture server via `php -S` with routes that emulate: a PHP host leaking `X-Powered-By`, a host serving a fake `.env`, a host with a webshell path, a host with missing headers. The engine is run against `127.0.0.1` and asserted to produce the expected findings.

**TUI** — render the widgets against `DummyBackend` and assert the frame contains the expected strings; no terminal required, so it runs in CI.

## 16. Delivery phases

| Phase | Contents | Exit criterion |
|---|---|---|
| **P1** | Composer skeleton, `Config`, `Target`, `Http\Client`, `Http\Pool`, `Engine`, core checks, `Finding`, `Report` (text/json/markdown), `../../bin/php2scan` | `php2scan --config php2scan.yaml --format text` produces a correct report against the fixture server |
| **P2** | `Ui\TuiRenderer` with live progress, scrollable findings, expanded reproduce view, key handling | TUI renders and scrolls on a real terminal; `--no-tui` still works |
| **P3** | Crawler + `SqlInjection`, `ReflectedXss`, `LocalFileInclusion`, gated behind `--verify` | injection checks confirmed against fixture server; verification off by default |
| **P4** *(optional)* | Optional `nuclei` passthrough for breadth | not committed unless requested |

Each phase is independently shippable and independently useful; P1 alone already answers G1 and G3.

## 17. Decisions taken

| Decision | Rationale |
|---|---|
| Scope file is the only target source | Makes "authorized only" a structural property, not a convention |
| PHP2Shell is not exploited by the tool | The PoC is a worker crash; version is the authoritative exposure signal per the advisory |
| Reproduce steps are data files | Editable without touching PHP; the TUI can render them verbatim |
| One `Report` class, format switch | Avoids three near-identical classes for three formats |
| `symfony/dom-crawler` only in P3 | Keeps P1's dependency set minimal |
| No nuclei wrapper in the core | Adds a Go/Perl install and template-curation burden; breadth is not the goal |
| PHPUnit | Ecosystem standard; the dependency cost is one dev package |

## 18. Open items for review

1. **Default port list** for `open_ports` — proposed: `21, 22, 25, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017`.
2. **`min_severity: medium` default** — `low`/`info` findings (e.g. "not affected") are still shown in the TUI and in JSON output, but excluded from the text report and from the exit code unless configured otherwise.
3. **Reproduce-step substitution** — steps use the literal host; confirm the desired format for origin-IP targets with a `vhost` override (`https://1.2.3.4/` + `Host: legacy.example.com`).

---

## Appendix A — Verified `php-tui` API notes

Confirmed by installing `php-tui/php-tui 0.2.1` + `php-tui/term 0.3.4` on PHP 8.5.12 and rendering frames.

- `DisplayBuilder::default(?Backend)` → `->build()` → `Display`. Default backend is `PhpTermBackend` (terminal); `DummyBackend(w, h)` for tests.
- `Display::draw(Widget)` renders **and** flushes. Do not call `Display::flush()` afterwards — it blanks the screen.
- Vertical stacking: `GridWidget::default()->direction(Direction::Vertical)->constraints(Constraint::length(6), Constraint::min(0))->widgets($a, $b)`.
- `BlockWidget::default()->borders(Borders::ALL)->titles(Title::fromString('…'))->widget($inner)`.
- `TableWidget::default()->header(TableRow::fromCells(TableCell::fromString('a'), …))->rows($row1, $row2)->widths(Constraint::percentage(50), …)` — **`rows()`, `widths()`, `fromCells()`, `fromLines()`, `fromSpans()` are variadic**, not array-taking.
- `Line::fromString()`, `Span::fromString()`, `Span::styled($text, Style::default()->fg(AnsiColor::Yellow))`; colours via `AnsiColor::fromName('yellow')` or the enum cases.
- `Display::insertBefore(int $height, Widget)` works only with the `inline()` viewport — the fullscreen layout uses `GridWidget` instead.
- `Terminal::new()->events()->next()` is **non-blocking** (`StreamReader` sets STDIN non-blocking), so it is safe to poll inside a render loop.
- Terminal size comes from `stty` (via `SizeFromSttyProvider`) with an env-var fallback → the TUI is gated on `stream_isatty(STDOUT)`.
