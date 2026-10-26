# PHP2Shell-TUI 

Exposure scanner for **CVE-2026-109618** / **CVE-2026-109619** ("PHP2Shell") and general web
misconfiguration. Each finding carries evidence, a one-sentence exploit line, and runnable
reproduce steps.

It only contacts the hosts listed in your config — no discovery, no host argument, no brute force.
Use it only on hosts you own or are authorized to test.

**Note:** The default scan is detection-only: version, phpinfo/SAPI and the chain preconditions,
with no POST. With `--verify` it runs the real parametric PHP2Shell chain only when the target
matches one of the five calibrated build profiles. A failed attempt is reported as "proof not
obtained", never as safe. There is no canary and no arming probe. HTTPS uses verified TLS but is
not lab-verified; FPM is refused because the calibrated chain is mod_php only.

<img src="./screenshot.png" alt="php2shell-tui" width="600">

## Requirements

- PHP 8.2+ with `curl`, `json` and `openssl` (all standard)
- Composer

## Install
Download [php2shell-tui](https://github.com/uchm4n/php2shell-tui/raw/refs/heads/main/php2shell-tui)

## Configure
Edit `php2shell-tui.yaml` it is a default configuration file. 
You can also specify a different config file with `./php2shell-tui scan --config other.yaml`


```yaml
targets:
  - https://example.com
  - https://example1.com
  - https://example2.com
  - https://example3.com
  
  - url: https://legacy.example4.com
    paths: ["/wp-content/uploads"]

  - url: https://legacy.example5.com
    paths: [ "/admin", "/wp-admin", "/login" ]
    
  - url: https://203.0.113.10/
    vhost: legacy.example.com        # Host: header to send to that IP
    paths: ["/wp-content/uploads"]   # extra directories to check for webshells

  # Optional real-server check. No POST is sent without --verify.
  # post_path selects the chain endpoint and the proof candidates.
  - url: https://app.example.com/
    post_path: /index.php

checks:
  php_presence: true
  php_version: true
  php2shell: true                    # default on; POST only with --verify
  sensitive_files: true
  security_headers: true
  tls: true
  app_fingerprint: true
  webshell_indicators: true
  open_ports: true
  injection: false                   # also needs --verify

poc:
  workers: 150                       # target prefork MaxRequestWorkers; 1 for a single-worker lab
  # memory_limit: 128                # optional MiB; omit to use phpinfo or the OOM probe
  timeout: 300                       # overall seconds for one verification
  request_timeout: 90                # per raw request
  retries: 3                         # stage1/stage2; stage3 uses retries + 2
  max_workers: 200                   # refuse a config above this pin count
  # profile: php-8.4.26-bookworm-amd64 # optional exact override

options:
  concurrency: 8
  timeout: 10                        # seconds per request
  connect_timeout: 5
  delay_ms: 100                      # per-host politeness delay
  min_severity: medium               # below this: hidden from text/markdown and the exit code

output:
  format: tui                        # tui | text | json | markdown
  report_dir: ./reports
```

## Usage

```bash
./php2shell-tui scan                     # scan; TUI when attached to a terminal
./php2shell-tui scan --format json       # pipeable JSON on stdout
./php2shell-tui scan --format markdown --output-dir ./out
./php2shell-tui scan --config other.yaml
```

The results stay on screen when the scan finishes: the target table shows the final state of every
host, the findings pane stays interactive, and a failure is shown in a red banner instead of
dropping back to the shell. Press `q`, `Esc` or `Ctrl-C` to close the TUI; press `r` to restart the
whole scan (`j`/`k` or arrows move, `Enter` expands a finding). The report is still written to
`report_dir`.

Exit codes: `0` clean, `1` findings at or above `min_severity`, `2` error, `130` cancelled from the TUI.

When `--verify` is set, the scanner selects exactly one calibrated build:

- **auto:** the exact `x.y.z` advertised by the target, or `--php-version x.y.z` when the version
  is hidden; `--arch` is required when a version has both amd64 and aarch64 profiles.
- **explicit:** `--profile <id|path>` or a target `poc_profile`.

`--workers` (or `poc.workers`) is the target's prefork `MaxRequestWorkers`; use `1` for a
single-worker lab. It is required: the scanner will not pin an unknown worker pool.

Each attempt pins `workers - 1` connections, runs the real parametric chain (rotate, stage 1 heap
leak, stage 2 libphp leak, stage 3 fake HashTable), writes a one-character proof file, and fetches
both `<post_path directory>/<file>` and `/<file>`. **Critical** is emitted only when the exact
unique marker is returned. A failed attempt is “proof not obtained,” never “safe.”

Before a payload is sent, the scanner requires: the exact version+arch profile, mod_php,
`session.upload_progress.enabled=On`, `display_errors=On`, `session.use_strict_mode=0`, a finite
`memory_limit`, and `post_max_size` above `memory_limit + 12`. Known failures send zero payload.
The chain is intrusive — worker rotation, half-open pinning, 12 MB+ bodies — so run it only with
authorization. The TUI shows `verify 1/1`; press `r` to abort and restart.

**Known limitation**: a baseline response of `403`, `407`, `429`, or `503` marks the target unscannable
and skips every check, including the active proof. Use a baseline path the scanner can reach, or
run it from a vantage point that can reach the application.

`injection: true` adds SQL injection, reflected XSS, and local file inclusion probes. They also
stay off until `--verify`:

```bash
bin/php2shell-tui scan --verify          # --verify is the explicit authorization
```

Rails: the full chain pins `workers - 1` connections plus the parametric chain requests. Hosts
outside the target are never contacted, pages that differ between two identical fetches are
skipped, and findings ship reproduce steps rather than a destructive payload.

## What it looks for

- PHP versions below the PHP2Shell fix (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12), including EOL branches
  and release candidates
- A consolidated exploitability finding from phpinfo: SAPI, `session.upload_progress`,
  `display_errors`, `session.use_strict_mode`, `memory_limit`, `post_max_size`, and the matching
  calibrated profile
- Exposed secrets and debug files: `.env`, backups, `phpinfo`, database consoles
- Missing or weak security headers (CSP, HSTS, frame and content-type protections)
- TLS certificates that are expired, expiring soon, or issued for another hostname
- Webshell indicators in common upload paths
- Publicly reachable high-risk ports
- With `--verify` and a matching calibrated build: a real, unique-marker RCE proof
- With `--verify` and `injection: true`: SQL injection, reflected XSS, local file inclusion

## Calibrated verification

Five exact builds have public RCE calibration. Everything else is detection-only.

| PHP | architecture | profile id |
|---|---|---|
| 8.4.25 | aarch64 | `php-8.4.25-bookworm-aarch64` |
| 8.4.26 | amd64 | `php-8.4.26-bookworm-amd64` |
| 8.5.10 | aarch64 | `php-8.5.10-bookworm-aarch64` |
| 8.5.11 | aarch64 | `php-8.5.11-bookworm-aarch64` |
| 8.5.11 | amd64 | `php-8.5.11-bookworm-amd64` |

A version is not a build: the offsets and heap calibration are per build. The scanner refuses a
branch (`8.5`), a version without a profile, an unknown architecture, or an unverified profile.
PHP 7.4–8.3 are reported as affected but have no calibrated RCE profile.

The proof writes a one-character file in the PHP working directory and fetches both the script
directory and webroot candidates. If neither returns the marker, the finding says “proof not
retrievable”; it never claims success without the marker.

HTTPS uses verified TLS but is not lab-verified; treat it as experimental. FPM is refused because
the calibrated chain is mod_php only.

```sh
# detection only, no POST
bin/php2shell-tui scan --config target.yaml --no-tui --format json

# real chain: exact build, target MaxRequestWorkers
bin/php2shell-tui scan --config target.yaml --no-tui --format json --verify \
  --php-version 8.4.26 --arch amd64 --workers 150

# hidden version, operator-known build
bin/php2shell-tui scan --config target.yaml --no-tui --format json --verify \
  --profile php-8.5.11-bookworm-aarch64 --workers 150 --memory-limit 128
```

## Development

Build the PHAR with `composer build`, then run `./php2shell-tui`.

```bash
composer test
```

The suite starts a local fixture server; nothing external is contacted. The release gate runs the
five builds in a disposable Docker matrix (positive proofs, patched/FPM/hidden-version negatives,
2/4-worker pinning) and the built PHAR; no lab files or Docker data are committed. Contributions:
branch, keep the suite green, open a pull request.

## License
MIT
