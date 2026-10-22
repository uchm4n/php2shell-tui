# PHP2Shell TUI 

Exposure scanner for CVE-2026-109618 / CVE-2026-109619 ("PHP2Shell") and general web
misconfiguration. Each finding carries evidence, a one-sentence exploit line, and runnable
reproduce steps.

It only contacts the hosts listed in your config — no discovery, no host argument, no brute force.
Use it only on hosts you own or are authorized to test.

## Requirements

- PHP 8.2+ with `curl`, `json` and `openssl` (all standard)
- Composer

## Install
Download [php2shell-tui](https://github.com/uchm4n/php2shell-tui/php2shell-tui).


## Configure

Edit `php2shell-tui.yaml`; it is read by default.

```yaml
targets:
  - https://www.example.com
  - url: https://203.0.113.10/
    vhost: legacy.example.com        # Host: header to send to that IP
    paths: ["/wp-content/uploads"]   # extra directories to check for webshells
    staging: true                    # no --yes prompt for --verify

checks:
  php_presence: true
  php_version: true
  sensitive_files: true
  security_headers: true
  tls: true
  app_fingerprint: true
  webshell_indicators: true
  open_ports: true
  injection: false                   # phase 3, also needs --verify

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

TUI keys: `q`, `Esc` or `Ctrl-C` quit (`j`/`k` or arrows move, `Enter` expands a finding).

Exit codes: `0` clean, `1` findings at or above `min_severity`, `2` error, `130` cancelled from the TUI.

### Phase 3: proof-of-concept probes

`injection: true` adds SQL injection, reflected XSS and local file inclusion probes. They stay off
until you also pass `--verify` at runtime:

```bash
bin/php2shell-tui --verify          # asks before probing hosts not marked staging: true
bin/php2shell-tui --verify --yes    # no prompt
```

Rails: at most 60 probe requests per check per target, hosts outside the target are never
contacted, pages that differ between two identical fetches are skipped, and a finding ships
reproduce steps rather than a destructive payload.

## What it looks for

- PHP versions below the PHP2Shell fix (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12), including EOL branches
  and release candidates
- Exposed secrets and debug files: `.env`, backups, `phpinfo`, database consoles
- Missing or weak security headers (CSP, HSTS, frame and content-type protections)
- TLS certificates that are expired, expiring soon, or issued for another hostname
- Webshell indicators in common upload paths
- Publicly reachable high-risk ports
- With `--verify`: SQL injection, reflected XSS, local file inclusion

## Development

Build the PHAR with `composer build`, then run `./php2shell-tui`.

```bash
composer test
```

The suite starts a local fixture server; nothing external is contacted. Contributions: branch,
keep the suite green, open a pull request.

## License
MIT
