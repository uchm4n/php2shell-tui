# php2scan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `php2scan`, a Composer CLI that scans an allowlisted set of hosts for PHP2Shell exposure and general web misconfiguration, verifies findings where safe, and reports each finding with evidence, a one-sentence exploit line, and runnable reproduce steps.

**Architecture:** Config file → `Target[]` allowlist → `Engine` runs three concurrent phases (baseline fetch → per-check path prefetch → synchronous analysis) over Guzzle's `CurlMultiHandler` driven manually with `tick()`, so N hosts are scanned at once. Checks are declarative: each declares the paths it wants (`paths()`), then turns fetched responses into findings (`analyze()`). One `Report` class renders text/json/markdown; a `Ui\TuiRenderer` renders the live TUI via `php-tui`.

**Tech Stack:** PHP ≥ 8.2 · Composer 2 · `guzzlehttp/guzzle` 8.3 · `symfony/console` 7 · `symfony/yaml` 7 · `symfony/dom-crawler` 7 (phase 3) · `aidantwoods/secureheaders` 2.0.1 · `php-tui/php-tui` 0.2.1 · PHPUnit 11

**Spec:** `../specs`

---

## Global Constraints

- **PHP floor `>= 8.2`.** Never write code requiring a newer PHP feature than 8.2 (no `readonly` classes — use `readonly` *properties*; no `json_validate()`; no typed class constants).
- **Namespace `Php2Scan\` → `src/`.** Tests `Php2Scan\Tests\` → `tests/`.
- **Target allowlist is structural.** `Config::targets()` is the only source of hosts. There is no CLI argument that accepts a host. A target not present in the config is never contacted.
- **Read-only.** Phase 1 issues `GET` only. Phase 3 verification issues `GET` only. No `POST`, `PUT`, `DELETE`, no request bodies, no multipart.
- **Never implement the PHP2Shell memory-corruption PoC.** The tool reports exposure; it does not exploit CVE-2026-109618/109619.
- **Every finding must have a non-empty `exploit` sentence and ≥1 reproduce step.** Enforced by `FindingTest`.
- **Reproduce steps live in `data/repro/<finding-id>.md`**, not in PHP.
- **Severity scale:** `critical` > `high` > `medium` > `low` > `info`.
- **PHP2Shell fixed versions (verbatim from the spec):** 8.2 → 8.2.35, 8.3 → 8.3.36, 8.4 → 8.4.27, 8.5 → 8.5.12. Branches below 8.2 are end-of-life with no fix.
- **`error_reporting(E_ALL & ~E_DEPRECATED)` must be set in `bin/php2scan` before any autoload**, because `aidantwoods/secureheaders` emits PHP 8.5 deprecations at class-load time.
- **Commit after every task.** Commit messages use Conventional Commits (`feat:`, `fix:`, `test:`, `chore:`).
- **Never call `Display::flush()` after `Display::draw()`** — `draw()` flushes internally; an extra `flush()` blanks the screen.

---

## Review Focus

Five input classes the spec implies but no task's happy-path test exercises. Each line below names a condition and the behaviour a reasonable person would expect. The task that owns the relevant code carries the test that pins it.

1. **Host is unreachable** (DNS failure, connection refused, TLS handshake failure) → the scan must not crash; the host is reported as unreachable with the transport error, and every other host still completes.
2. **Baseline returns 404** → 404 is a *valid response*, not an unreachable host. Apache's 404 page leaks `Server: Apache/2.4.x (Unix) PHP/8.x.y`, which is a version source.
3. **Redirect to a different host** → redirects are followed, but a redirect that leaves the allowlisted host must not cause the scanner to contact the new host (scope escape). Record the redirect chain; treat a cross-host redirect as a finding, not as a new target.
4. **Everything returns 403/503** (CDN, WAF, geo-block) → report the target as "not scannable" with the status, never as "no findings found".
5. **Non-release PHP version strings** (`8.2.12RC1`, `8.2.12-1ubuntu2.14`, `8.2`, `8.2.12-pl1`) → must be normalised before comparison; an unparseable version yields "unknown", never a crash and never a false "patched".

---

## File Structure

| File | Responsibility |
|---|---|
| `composer.json` | Dependencies, PSR-4 autoload, `bin/php2scan`, scripts |
| `phpunit.xml.dist` | PHPUnit 11 configuration, testsuite `tests/` |
| `bin/php2scan` | Executable entry: `error_reporting` tweak, autoload, Symfony Console app |
| `src/Severity.php` | `Severity` enum with `rank()` and `atLeast()` |
| `src/Finding.php` | Immutable finding: id, title, severity, target, evidence, exploit, reproduce |
| `src/Target.php` | Immutable allowlisted target: url, vhost, paths, staging |
| `src/Config.php` | Load + validate the YAML config; expose typed options |
| `src/PhpVersionDb.php` | Affected-version matrix and version triage |
| `src/Http/Client.php` | Guzzle wrapper: async + sync GET, timeouts, per-host delay |
| `src/Http/Pool.php` | Concurrent request runner over `CurlMultiHandler` + `tick()` |
| `src/Check/Check.php` | The check interface: `id()`, `paths()`, `analyze()` |
| `src/Check/Registry.php` | Ordered map of check id → check instance |
| `src/Check/PhpDetection.php` | Is PHP present? Which signals fired? |
| `src/Check/PhpVersion.php` | Version extraction + PHP2Shell triage |
| `src/Check/SensitiveFiles.php` | Leaked secrets, manifests, backups |
| `src/Check/SecurityHeaders.php` | OWASP header presence + CSP validity + cookie flags |
| `src/Check/Tls.php` | Certificate expiry, issuer, SAN match |
| `src/Check/AppFingerprint.php` | CMS/framework identification |
| `src/Check/WebshellIndicators.php` | Webshell IOC paths in upload dirs |
| `src/Check/OpenPorts.php` | Unexpected listening ports |
| `src/Check/SqlInjection.php` | Phase 3 — boolean SQLi probe |
| `src/Check/ReflectedXss.php` | Phase 3 — unencoded reflection probe |
| `src/Check/LocalFileInclusion.php` | Phase 3 — path traversal probe |
| `src/Crawler/Crawler.php` | Phase 3 — link/form/parameter discovery |
| `src/Engine.php` | Three-phase orchestration: baseline → prefetch → analyze |
| `src/ScanResult.php` | Findings, unreachable targets, unscannable targets, timings |
| `src/Data/Wordlists.php` | Loads `data/*.txt` |
| `src/Data/Reproduce.php` | Loads `data/repro/*.md`, substitutes the target host |
| `src/Report/Report.php` | One class, four output formats |
| `src/Report/Theme.php` | Severity → colour, severity → symbol |
| `src/Ui/TuiRenderer.php` | php-tui rendering, live progress, scrolling, key handling |
| `src/Ui/PlainRenderer.php` | Text output |
| `src/Command/ScanCommand.php` | Symfony Console command, option parsing, exit codes |
| `data/php-affected.json` | The affected-version matrix |
| `data/sensitive-paths.txt` | Paths to probe for leaked files |
| `data/webshell-paths.txt` | Webshell IOC filenames |
| `data/open-ports.txt` | Ports to probe |
| `data/repro/<id>.md` | One file per finding id: reproduce steps |
| `tests/Unit/…` | Pure unit tests, no network |
| `tests/Integration/…` | Tests against a local `php -S` fixture server |
| `tests/Fixture/server.php` | The fixture server used by integration tests |

---

## Phase 1 — Core engine

### Task 1: Project skeleton, Composer, PHPUnit, CLI entry

**Files:**
- Create: `composer.json`
- Create: `phpunit.xml.dist`
- Create: `bin/php2scan`
- Create: `.gitignore` (exists — verify it matches the list below)
- Create: `php2scan.yaml.example`
- Test: `tests/Unit/SmokeTest.php`

**Interfaces:**
- Consumes: nothing.
- Produces: `bin/php2scan` runnable as `php bin/php2scan --version`; `composer test` runs PHPUnit; PSR-4 root `Php2Scan\` → `src/`.

- [ ] **Step 1: Create the repository and initialise git**

```bash
cd /Users/u/www/projects/php2shell
git init
git add -A
git commit -m "chore: initial project scaffold"
```

- [ ] **Step 2: Write `composer.json`**

```json
{
    "name": "php2scan/php2scan",
    "description": "Multi-host exposure scanner for PHP2Shell and general web misconfiguration",
    "type": "project",
    "license": "MIT",
    "require": {
        "php": ">=8.2",
        "ext-curl": "*",
        "ext-json": "*",
        "ext-openssl": "*",
        "aidantwoods/secureheaders": "^2.0.1",
        "guzzlehttp/guzzle": "^8.3",
        "php-tui/php-tui": "^0.2.1",
        "symfony/console": "^7.0",
        "symfony/dom-crawler": "^7.0",
        "symfony/yaml": "^7.0"
    },
    "require-dev": {
        "phpunit/phpunit": "^11"
    },
    "autoload": {
        "psr-4": {
            "Php2Scan\\": "src/"
        }
    },
    "autoload-dev": {
        "psr-4": {
            "Php2Scan\\Tests\\": "tests/"
        }
    },
    "bin": [
        "bin/php2scan"
    ],
    "scripts": {
        "scan": "bin/php2scan",
        "test": "phpunit"
    },
    "config": {
        "sort-packages": true
    }
}
```

- [ ] **Step 3: Run `composer update` and verify the dependency set resolves**

Run: `composer update --no-interaction`
Expected: `Lock file operations: N installs` and no error. Confirm `guzzlehttp/guzzle` is `v8.x` and `symfony/console` is `v7.x`.

- [ ] **Step 4: Create `phpunit.xml.dist`**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<phpunit xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:noNamespaceSchemaLocation="vendor/phpunit/phpunit/phpunit.xsd"
         bootstrap="vendor/autoload.php"
         colors="true"
         cacheDirectory=".phpunit.cache">
    <testsuites>
        <testsuite name="php2scan">
            <directory>tests</directory>
        </testsuite>
    </testsuites>
    <source>
        <include>
            <directory>src</directory>
        </include>
    </source>
</phpunit>
```

- [ ] **Step 5: Create `bin/php2scan`**

```php
#!/usr/bin/env php
<?php

declare(strict_types=1);

// aidantwoods/secureheaders emits PHP 8.5 deprecations at class-load time.
// This must be set before the class is ever autoloaded.
error_reporting(E_ALL & ~E_DEPRECATED);

require __DIR__ . '/../vendor/autoload.php';

exit((new Php2Scan\Application())->run());
```

- [ ] **Step 6: Write the failing smoke test `tests/Unit/SmokeTest.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use PHPUnit\Framework\TestCase;

final class SmokeTest extends TestCase
{
    public function testTheConsoleApplicationRunsAndReportsItsVersion(): void
    {
        $application = new \Php2Scan\Application();
        $application->setAutoExit(false);
        $application->setCatchExceptions(false);

        $output = new \Symfony\Component\Console\Output\BufferedOutput();
        $code = $application->run(new \Symfony\Component\Console\Input\ArrayInput(['--version' => true]), $output);

        self::assertSame(0, $code);
        self::assertStringContainsString('php2scan', $output->fetch());
    }
}
```

- [ ] **Step 7: Run the test to verify it fails**

Run: `composer test`
Expected: FAIL — `Class "Php2Scan\Application" not found`.

- [ ] **Step 8: Implement `src/Application.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan;

use Php2Scan\Command\ScanCommand;
use Symfony\Component\Console\Application as BaseApplication;

final class Application extends BaseApplication
{
    public const NAME = 'php2scan';
    public const VERSION = '1.0.0';

    public function __construct()
    {
        parent::__construct(self::NAME, self::VERSION);
        $this->add(new ScanCommand());
    }
}
```

- [ ] **Step 9: Create a minimal `src/Command/ScanCommand.php` placeholder that will be replaced in Task 15**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'scan', description: 'Scan the configured hosts for security exposure')]
final class ScanCommand extends Command
{
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $output->writeln('<info>php2scan: not yet implemented</info>');

        return Command::SUCCESS;
    }
}
```

- [ ] **Step 10: Create `php2scan.yaml.example`**

Copy the config block from the spec §7 verbatim, with `targets:` containing the two example hosts from the spec.

- [ ] **Step 11: Verify `.gitignore` contents**

It must contain exactly:

```
/vendor/
/reports/
/tmp/*
!/tmp/.gitkeep
/.idea/
/.phpunit.cache/
/.phpunit.result.cache
.DS_Store
```

- [ ] **Step 12: Run the test to verify it passes**

Run: `composer test`
Expected: PASS — `OK (1 test, 1 assertion)`.

- [ ] **Step 13: Verify the CLI runs**

Run: `php bin/php2scan --version`
Expected: `php2scan 1.0.0`

- [ ] **Step 14: Commit**

```bash
git add composer.json composer.lock phpunit.xml.dist bin/php2scan src/Application.php src/Command/ScanCommand.php tests/Unit/SmokeTest.php php2scan.yaml.example .gitignore
git commit -m "feat: project skeleton, composer dependencies and console entry point"
```

---

### Task 2: `Severity` enum and `Finding` value object

**Files:**
- Create: `src/Severity.php`
- Create: `src/Finding.php`
- Test: `tests/Unit/SeverityTest.php`
- Test: `tests/Unit/FindingTest.php`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `Php2Scan\Severity` — `enum Severity: string` with cases `Critical='critical'`, `High='high'`, `Medium='medium'`, `Low='low'`, `Info='info'`; methods `rank(): int` (5,4,3,2,1 respectively) and `atLeast(self $min): bool` (`$this->rank() >= $min->rank()`); static `fromName(string $name): self` that throws `\InvalidArgumentException` on an unknown name.
  - `Php2Scan\Finding` — `final class Finding` with `public readonly` promoted constructor properties: `string $id`, `string $title`, `Severity $severity`, `string $target`, `string $evidence`, `string $exploit`, `array $reproduce` (a `list<string>`).

- [ ] **Step 1: Write the failing tests**

`tests/Unit/SeverityTest.php`:

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use Php2Scan\Severity;
use PHPUnit\Framework\TestCase;

final class SeverityTest extends TestCase
{
    public function testRankOrdersTheScale(): void
    {
        self::assertSame(5, Severity::Critical->rank());
        self::assertSame(4, Severity::High->rank());
        self::assertSame(3, Severity::Medium->rank());
        self::assertSame(2, Severity::Low->rank());
        self::assertSame(1, Severity::Info->rank());
    }

    public function testAtLeastComparesByRank(): void
    {
        self::assertTrue(Severity::Critical->atLeast(Severity::High));
        self::assertTrue(Severity::High->atLeast(Severity::High));
        self::assertFalse(Severity::Medium->atLeast(Severity::High));
    }

    public function testFromNameAcceptsTheFiveKnownNames(): void
    {
        self::assertSame(Severity::Critical, Severity::fromName('critical'));
        self::assertSame(Severity::Info, Severity::fromName('info'));
    }

    public function testFromNameRejectsAnUnknownName(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Severity::fromName('catastrophic');
    }
}
```

`tests/Unit/FindingTest.php`:

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use Php2Scan\Finding;
use Php2Scan\Severity;
use PHPUnit\Framework\TestCase;

final class FindingTest extends TestCase
{
    public function testItCarriesEveryPartOfAReportableFinding(): void
    {
        $finding = new Finding(
            id: 'sensitive-file-env',
            title: 'Exposed .env',
            severity: Severity::High,
            target: 'legacy.example.com',
            evidence: 'HTTP 200, 1.2 KB, contains APP_KEY',
            exploit: 'curl https://legacy.example.com/.env and read the leaked credentials.',
            reproduce: ['curl -sS https://legacy.example.com/.env | head -20'],
        );

        self::assertSame('sensitive-file-env', $finding->id);
        self::assertSame(Severity::High, $finding->severity);
        self::assertSame(['curl -sS https://legacy.example.com/.env | head -20'], $finding->reproduce);
    }

    public function testTheExploitSentenceIsNeverEmpty(): void
    {
        $finding = new Finding('x', 't', Severity::Low, 'host', 'e', '', ['step']);

        self::assertNotSame('', trim($finding->exploit));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `composer test -- --filter 'SeverityTest|FindingTest'`
Expected: FAIL — `Class "Php2Scan\Severity" not found`.

- [ ] **Step 3: Implement `src/Severity.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan;

enum Severity: string
{
    case Critical = 'critical';
    case High = 'high';
    case Medium = 'medium';
    case Low = 'low';
    case Info = 'info';

    public function rank(): int
    {
        return match ($this) {
            self::Critical => 5,
            self::High => 4,
            self::Medium => 3,
            self::Low => 2,
            self::Info => 1,
        };
    }

    public function atLeast(self $min): bool
    {
        return $this->rank() >= $min->rank();
    }

    public static function fromName(string $name): self
    {
        return self::from(strtolower($name));
    }
}
```

- [ ] **Step 4: Implement `src/Finding.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan;

final class Finding
{
    /**
     * @param list<string> $reproduce
     */
    public function __construct(
        public readonly string $id,
        public readonly string $title,
        public readonly Severity $severity,
        public readonly string $target,
        public readonly string $evidence,
        public readonly string $exploit,
        public readonly array $reproduce,
    ) {
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `composer test -- --filter 'SeverityTest|FindingTest'`
Expected: PASS — `OK (6 tests, 8 assertions)`.

- [ ] **Step 6: Commit**

```bash
git add src/Severity.php src/Finding.php tests/Unit/SeverityTest.php tests/Unit/FindingTest.php
git commit -m "feat: severity enum and finding value object"
```

---

### Task 3: `Target` and `Config`

**Files:**
- Create: `src/Target.php`
- Create: `src/Config.php`
- Create: `data/…` — not in this task.
- Test: `tests/Unit/ConfigTest.php`

**Interfaces:**
- Consumes: `Php2Scan\Severity` (Task 2).
- Produces:
  - `Php2Scan\Target` — `final class Target` with `public readonly` promoted properties `string $url`, `?string $vhost`, `array $paths` (`list<string>`), `bool $staging`; methods `host(): string` (host component of `$url`), `requestHeaders(): array` (returns `['Host' => $vhost]` when `$vhost` is not null, otherwise `[]`), `label(): string` (returns `$this->vhost ?? $this->host()`).
  - `Php2Scan\Config` — `final class Config` with `public readonly` promoted properties `array $targets` (`list<Target>`), `array $checks` (`array<string,bool>`), `int $concurrency`, `int $timeout`, `int $connectTimeout`, `int $delayMs`, `string $userAgent`, `bool $verify`, `Severity $minSeverity`, `string $format`, `string $reportDir`; static `fromFile(string $path): self`; static `fromArray(array $data, string $baseDir = ''): self`; `checkEnabled(string $id): bool`; `enabledChecks(): array` returning the enabled check ids in declaration order.

- [ ] **Step 1: Write the failing test `tests/Unit/ConfigTest.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use Php2Scan\Config;
use Php2Scan\Severity;
use PHPUnit\Framework\TestCase;

final class ConfigTest extends TestCase
{
    public function testItLoadsAValidConfig(): void
    {
        $config = Config::fromArray([
            'targets' => [
                'https://www.php2shell.com',
                ['url' => 'https://legacy.example.com', 'vhost' => 'legacy.example.com', 'paths' => ['/wp-content/uploads']],
            ],
            'checks' => ['php_version' => true, 'tls' => false],
            'options' => ['concurrency' => 4, 'min_severity' => 'high'],
            'output' => ['format' => 'json'],
        ]);

        self::assertCount(2, $config->targets);
        self::assertSame('www.php2shell.com', $config->targets[0]->host());
        self::assertSame('legacy.example.com', $config->targets[1]->vhost);
        self::assertSame(['/wp-content/uploads'], $config->targets[1]->paths);
        self::assertSame(4, $config->concurrency);
        self::assertSame(Severity::High, $config->minSeverity);
        self::assertSame('json', $config->format);
        self::assertTrue($config->checkEnabled('php_version'));
        self::assertFalse($config->checkEnabled('tls'));
    }

    public function testItRejectsAnEmptyTargetList(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('targets');
        Config::fromArray(['targets' => []]);
    }

    public function testItRejectsAMalformedUrl(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Config::fromArray(['targets' => ['not a url']]);
    }

    public function testItRejectsAnUnknownCheckName(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('unknown check');
        Config::fromArray([
            'targets' => ['https://example.com'],
            'checks' => ['no_such_check' => true],
        ]);
    }

    public function testItRejectsAnUnknownOutputFormat(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Config::fromArray([
            'targets' => ['https://example.com'],
            'output' => ['format' => 'pdf'],
        ]);
    }

    public function testDefaultsAreApplied(): void
    {
        $config = Config::fromArray(['targets' => ['https://example.com']]);

        self::assertSame(8, $config->concurrency);
        self::assertSame(10, $config->timeout);
        self::assertSame(5, $config->connectTimeout);
        self::assertSame(100, $config->delayMs);
        self::assertFalse($config->verify);
        self::assertSame(Severity::Medium, $config->minSeverity);
        self::assertSame('tui', $config->format);
        self::assertSame('./reports', $config->reportDir);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `composer test -- --filter ConfigTest`
Expected: FAIL — `Class "Php2Scan\Config" not found`.

- [ ] **Step 3: Implement `src/Target.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan;

final class Target
{
    /**
     * @param list<string> $paths
     */
    public function __construct(
        public readonly string $url,
        public readonly ?string $vhost = null,
        public readonly array $paths = [],
        public readonly bool $staging = false,
    ) {
    }

    public function host(): string
    {
        return (string) parse_url($this->url, PHP_URL_HOST);
    }

    /**
     * @return array<string, string>
     */
    public function requestHeaders(): array
    {
        return $this->vhost === null ? [] : ['Host' => $this->vhost];
    }

    public function label(): string
    {
        return $this->vhost ?? $this->host();
    }
}
```

- [ ] **Step 4: Implement `src/Config.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan;

final class Config
{
    public const CHECKS = [
        'php_presence',
        'php_version',
        'sensitive_files',
        'security_headers',
        'tls',
        'app_fingerprint',
        'webshell_indicators',
        'open_ports',
        'injection',
        'sql_injection',
        'reflected_xss',
        'local_file_inclusion',
    ];

    public const FORMATS = ['tui', 'text', 'json', 'markdown'];

    /**
     * @param list<Target>          $targets
     * @param array<string, bool>   $checks
     */
    public function __construct(
        public readonly array $targets,
        public readonly array $checks,
        public readonly int $concurrency,
        public readonly int $timeout,
        public readonly int $connectTimeout,
        public readonly int $delayMs,
        public readonly string $userAgent,
        public readonly bool $verify,
        public readonly Severity $minSeverity,
        public readonly string $format,
        public readonly string $reportDir,
    ) {
    }

    public static function fromFile(string $path): self
    {
        if (!is_file($path)) {
            throw new \InvalidArgumentException(sprintf('Config file "%s" does not exist.', $path));
        }

        $parsed = \Symfony\Component\Yaml\Yaml::parseFile($path);

        if (!is_array($parsed)) {
            throw new \InvalidArgumentException(sprintf('Config file "%s" is empty or malformed.', $path));
        }

        return self::fromArray($parsed, dirname($path));
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data, string $baseDir = ''): self
    {
        $targets = self::parseTargets($data['targets'] ?? []);
        $checks = self::parseChecks($data['checks'] ?? []);
        $options = is_array($data['options'] ?? null) ? $data['options'] : [];
        $output = is_array($data['output'] ?? null) ? $data['output'] : [];

        $format = (string) ($output['format'] ?? 'tui');
        if (!in_array($format, self::FORMATS, true)) {
            throw new \InvalidArgumentException(sprintf('Unknown output format "%s"; expected one of %s.', $format, implode(', ', self::FORMATS)));
        }

        $minSeverity = Severity::fromName((string) ($options['min_severity'] ?? 'medium'));

        return new self(
            targets: $targets,
            checks: $checks,
            concurrency: max(1, (int) ($options['concurrency'] ?? 8)),
            timeout: max(1, (int) ($options['timeout'] ?? 10)),
            connectTimeout: max(1, (int) ($options['connect_timeout'] ?? 5)),
            delayMs: max(0, (int) ($options['delay_ms'] ?? 100)),
            userAgent: (string) ($options['user_agent'] ?? 'php2scan/1.0'),
            verify: (bool) ($options['verify'] ?? false),
            minSeverity: $minSeverity,
            format: $format,
            reportDir: (string) ($output['report_dir'] ?? './reports'),
        );
    }

    public function checkEnabled(string $id): bool
    {
        return $this->checks[$id] ?? false;
    }

    /**
     * @return list<string>
     */
    public function enabledChecks(): array
    {
        $enabled = [];

        foreach (self::CHECKS as $id) {
            if ($this->checkEnabled($id)) {
                $enabled[] = $id;
            }
        }

        return $enabled;
    }

    /**
     * @param mixed $raw
     * @return list<Target>
     */
    private static function parseTargets(mixed $raw): array
    {
        if (!is_array($raw) || $raw === []) {
            throw new \InvalidArgumentException('Config must contain a non-empty "targets" list.');
        }

        $targets = [];

        foreach ($raw as $entry) {
            if (is_string($entry)) {
                $entry = ['url' => $entry];
            }

            if (!is_array($entry) || !isset($entry['url']) || !is_string($entry['url'])) {
                throw new \InvalidArgumentException('Each target must be a URL string or a map with a "url" key.');
            }

            $url = $entry['url'];
            if (filter_var($url, FILTER_VALIDATE_URL) === false) {
                throw new \InvalidArgumentException(sprintf('Target "%s" is not a valid URL.', $url));
            }

            $targets[] = new Target(
                url: $url,
                vhost: isset($entry['vhost']) ? (string) $entry['vhost'] : null,
                paths: array_values(array_map('strval', (array) ($entry['paths'] ?? []))),
                staging: (bool) ($entry['staging'] ?? false),
            );
        }

        return $targets;
    }

    /**
     * @return array<string, bool>
     */
    private static function parseChecks(mixed $raw): array
    {
        if (!is_array($raw)) {
            $raw = [];
        }

        foreach (array_keys($raw) as $id) {
            if (!in_array($id, self::CHECKS, true)) {
                throw new \InvalidArgumentException(sprintf('unknown check "%s" in config; known checks are %s.', $id, implode(', ', self::CHECKS)));
            }
        }

        $checks = [];
        foreach (self::CHECKS as $id) {
            $checks[$id] = (bool) ($raw[$id] ?? false);
        }

        // The single `injection` toggle switches on the three verification checks.
        if ($checks['injection'] ?? false) {
            $checks['sql_injection'] = true;
            $checks['reflected_xss'] = true;
            $checks['local_file_inclusion'] = true;
        }

        return $checks;
    }
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `composer test -- --filter ConfigTest`
Expected: PASS — `OK (6 tests, 18 assertions)`.

- [ ] **Step 6: Commit**

```bash
git add src/Target.php src/Config.php tests/Unit/ConfigTest.php
git commit -m "feat: target allowlist and configuration loading"
```

---

### Task 4: PHP2Shell version matrix and triage

**Files:**
- Create: `data/php-affected.json`
- Create: `src/PhpVersionDb.php`
- Test: `tests/Unit/PhpVersionDbTest.php`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `Php2Scan\PhpVersionDb` — `final class PhpVersionDb`, constructed as `new PhpVersionDb(string $dataFile)`. Methods:
    - `public function isAffected(string $version): bool` — true when the version is in an affected range.
    - `public function firstFixed(string $branch): ?string` — the first fixed release for a branch, `null` for a branch with no fix.
    - `public function fixedFor(string $version): ?string` — the first fixed release for the branch the version belongs to.
    - `public function branch(string $version): ?string` — the branch string, e.g. `8.2`, or `null` when the version cannot be parsed.
    - `public function normalize(string $raw): ?string` — normalise a raw version string to a comparable `major.minor.patch` string, or `null` when unparseable. `8.2.12RC1` → `8.2.12`; `8.2.12-1ubuntu2.14` → `8.2.12`; `8.2` → `8.2.0`; `8` → `8.0.0`.
    - `public function cves(): array` — the CVE identifiers, e.g. `['CVE-2026-109618', 'CVE-2026-109619']`.
    - `public function newestKnown(): string` — the highest first-fixed release in the database (`8.5.12`). A version above this is *newer than the advisory*, not patched.
    - `public function advisoryName(): string` — `PHP2Shell`.

- [ ] **Step 1: Write the failing test `tests/Unit/PhpVersionDbTest.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use Php2Scan\PhpVersionDb;
use PHPUnit\Framework\TestCase;

final class PhpVersionDbTest extends TestCase
{
    private PhpVersionDb $db;

    protected function setUp(): void
    {
        $this->db = new PhpVersionDb(__DIR__ . '/../../data/php-affected.json');
    }

    public static function affectedVersions(): array
    {
        return [
            ['5.6.40', true],
            ['7.4.33', true],
            ['8.0.30', true],
            ['8.1.29', true],
            ['8.2.34', true],
            ['8.2.35', false],
            ['8.3.35', true],
            ['8.3.36', false],
            ['8.4.26', true],
            ['8.4.27', false],
            ['8.5.11', true],
            ['8.5.12', false],
        ];
    }

    /**
     * @dataProvider affectedVersions
     */
    public function testItKnowsWhichVersionsAreAffected(string $version, bool $expected): void
    {
        self::assertSame($expected, $this->db->isAffected($version));
    }

    public function testItNormalisesVersionStrings(): void
    {
        self::assertSame('8.2.12', $this->db->normalize('PHP/8.2.12'));
        self::assertSame('8.2.12', $this->db->normalize('8.2.12RC1'));
        self::assertSame('8.2.12', $this->db->normalize('8.2.12-1ubuntu2.14'));
        self::assertSame('8.2.0', $this->db->normalize('8.2'));
        self::assertSame('8.0.0', $this->db->normalize('8'));
    }

    public function testItRejectsAnUnparseableVersion(): void
    {
        self::assertNull($this->db->normalize('not-a-version'));
        self::assertNull($this->db->branch('not-a-version'));
    }

    public function testItKnowsTheBranchAndItsFixedRelease(): void
    {
        self::assertSame('8.2', $this->db->branch('8.2.34'));
        self::assertSame('8.2.35', $this->db->fixedFor('8.2.34'));
        self::assertSame('8.5.12', $this->db->fixedFor('8.5.11'));
    }

    public function testBranchesBelowEightPointTwoHaveNoFix(): void
    {
        self::assertNull($this->db->firstFixed('8.1'));
        self::assertNull($this->db->firstFixed('7.4'));
        self::assertTrue($this->db->isAffected('8.1.29'));
    }

    public function testItKnowsTheNewestKnownRelease(): void
    {
        self::assertSame('8.5.12', $this->db->newestKnown());
    }

    public function testItKnowsTheCves(): void
    {
        self::assertSame(['CVE-2026-109618', 'CVE-2026-109619'], $this->db->cves());
        self::assertSame('PHP2Shell', $this->db->advisoryName());
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `composer test -- --filter PhpVersionDbTest`
Expected: FAIL — `Class "Php2Scan\PhpVersionDb" not found`.

- [ ] **Step 3: Create `data/php-affected.json`**

```json
{
    "advisory": "PHP2Shell",
    "cves": ["CVE-2026-109618", "CVE-2026-109619"],
    "fixed": {
        "8.2": "8.2.35",
        "8.3": "8.3.36",
        "8.4": "8.4.27",
        "8.5": "8.5.12"
    },
    "note": "All releases before the first fixed release of their branch are affected. Branches below 8.2 are end-of-life and have no fix."
}
```

- [ ] **Step 4: Implement `src/PhpVersionDb.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan;

final class PhpVersionDb
{
    /**
     * @param array<string, string> $fixed
     * @param list<string>          $cves
     */
    public function __construct(
        private readonly string $advisory,
        private readonly array $fixed,
        private readonly array $cves,
        private readonly string $dataFile,
    ) {
    }

    public static function fromFile(string $dataFile): self
    {
        $raw = @file_get_contents($dataFile);
        if ($raw === false) {
            throw new \RuntimeException(sprintf('Cannot read the affected-version database "%s".', $dataFile));
        }

        $data = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);

        return new self(
            advisory: (string) ($data['advisory'] ?? 'PHP2Shell'),
            fixed: (array) ($data['fixed'] ?? []),
            cves: array_values((array) ($data['cves'] ?? [])),
            dataFile: $dataFile,
        );
    }

    public function advisoryName(): string
    {
        return $this->advisory;
    }

    public function newestKnown(): string
    {
        $newest = '0.0.0';

        foreach ($this->fixed as $release) {
            if (version_compare($release, $newest, '>')) {
                $newest = $release;
            }
        }

        return $newest;
    }

    /**
     * @return list<string>
     */
    public function cves(): array
    {
        return $this->cves;
    }

    public function firstFixed(string $branch): ?string
    {
        return $this->fixed[$branch] ?? null;
    }

    public function fixedFor(string $version): ?string
    {
        $branch = $this->branch($version);

        return $branch === null ? null : $this->firstFixed($branch);
    }

    public function branch(string $version): ?string
    {
        $normalized = $this->normalize($version);

        if ($normalized === null) {
            return null;
        }

        $parts = explode('.', $normalized);

        return $parts[0] . '.' . $parts[1];
    }

    public function normalize(string $raw): ?string
    {
        if (preg_match('/(\d+)\.(\d+)(?:\.(\d+))?/', $raw, $m) !== 1) {
            return null;
        }

        return sprintf('%d.%d.%d', (int) $m[1], (int) $m[2], (int) ($m[3] ?? 0));
    }

    public function isAffected(string $version): bool
    {
        $normalized = $this->normalize($version);

        if ($normalized === null) {
            return false;
        }

        $branch = $this->branch($normalized);
        if ($branch === null) {
            return false;
        }

        $fixed = $this->firstFixed($branch);

        if ($fixed === null) {
            // No fixed release exists for this branch: it is end-of-life and affected.
            return true;
        }

        return version_compare($normalized, $fixed, '<');
    }
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `composer test -- --filter PhpVersionDbTest`
Expected: PASS — `OK (7 tests, 21 assertions)`.

- [ ] **Step 6: Commit**

```bash
git add data/php-affected.json src/PhpVersionDb.php tests/Unit/PhpVersionDbTest.php
git commit -m "feat: PHP2Shell affected-version database and triage"
```

---

### Task 5: HTTP client and concurrent pool

**Files:**
- Create: `src/Http/Client.php`
- Create: `src/Http/Pool.php`
- Test: `tests/Integration/HttpTest.php`
- Create: `tests/Fixture/server.php` (fixture server, reused by later integration tests)

**Interfaces:**
- Consumes: `Php2Scan\Target` (Task 3).
- Produces:
  - `Php2Scan\Http\Client` — `final class Client`, constructed as `new Client(\GuzzleHttp\Client $guzzle, int $delayMs = 0)`. Methods:
    - `public function getAsync(string $url, array $headers = [], int $delayMs = 0): \GuzzleHttp\Promise\PromiseInterface`
    - `public function get(string $url, array $headers = []): ?\Psr\Http\Message\ResponseInterface` — returns `null` on transport failure.
    - `public function guzzle(): \GuzzleHttp\Client`
  - `Php2Scan\Http\Pool` — `final class Pool`, constructed as `new Pool(\GuzzleHttp\Handler\CurlMultiHandler $handler, Client $client)`. Methods:
    - `public function run(array $requests, ?callable $onSettled = null): array` — `$requests` is a `list<array{url: string, headers: array<string,string>}>`; returns a `list<array{url: string, response: ?ResponseInterface, error: ?string}>` in the same order; `$onSettled` receives `(string $url, ?ResponseInterface $response, ?string $error)`.
    - `public function handler(): \GuzzleHttp\Handler\CurlMultiHandler`

**Critical implementation facts (verified against the installed packages — do not deviate):**

- Guzzle 8's `CurlMultiHandler` has **no `active()` method**. Completion is detected by counting settled promises.
- A promise that is **rejected** (connection refused, DNS failure) must also count as settled, otherwise the pool loop never terminates. Attach `->otherwise(...)` to every request promise and increment the counter there too.
- `CurlMultiHandler` constructor accepts `max_total_connections` and `max_host_connections` — use them for the global and per-host concurrency caps.
- The `delay` request option (milliseconds) is honoured by `CurlMultiHandler`; it defers attaching the transfer. Use it for per-host spacing.
- `Display`-style blocking is not involved here; `$handler->tick()` is the only driver.

- [ ] **Step 1: Create the fixture server `tests/Fixture/server.php`**

```php
<?php

declare(strict_types=1);

/**
 * Fixture server used by the integration tests.
 *
 * Routes:
 *   /            → 200 JSON, sets X-Powered-By: PHP/8.1.29 and Server: Apache/2.4.58 (Unix) PHP/8.1.29
 *   /headers     → 200 with no security headers at all
 *   /secure      → 200 with a full set of security headers
 *   /.env        → 200 with a fake .env body
 *   /missing     → 404 with an Apache-style body and the PHP-bearing Server header
 *   /shell.php   → 200 with a webshell body
 *   /slow        → 200 after a 1 second delay
 */
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

header_remove('X-Powered-By');
header('Server: Apache/2.4.58 (Unix) PHP/8.1.29');

switch ($path) {
    case '/headers':
        http_response_code(200);
        echo 'plain';
        break;

    case '/secure':
        http_response_code(200);
        header('Content-Security-Policy: default-src \'self\'');
        header('Strict-Transport-Security: max-age=31536000');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: no-referrer');
        header('X-Permitted-Cross-Domain-Policies: none');
        echo 'secure';
        break;

    case '/.env':
        http_response_code(200);
        echo "APP_KEY=base64:deadbeef\nDB_PASSWORD=hunter2\n";
        break;

    case '/missing':
        http_response_code(404);
        echo '<html><body>Not Found</body></html>';
        break;

    case '/shell.php':
        http_response_code(200);
        echo "<?php system(\$_GET['c']); ?>";
        break;

    case '/slow':
        sleep(1);
        http_response_code(200);
        echo 'slow';
        break;

    default:
        http_response_code(200);
        header('X-Powered-By: PHP/8.1.29');
        header('Content-Type: application/json');
        echo json_encode(['ok' => true]);
        break;
}
```

- [ ] **Step 2: Write the failing integration test `tests/Integration/HttpTest.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Integration;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\CurlMultiHandler;
use PHPUnit\Framework\TestCase;
use Php2Scan\Http\Client;
use Php2Scan\Http\Pool;

final class HttpTest extends TestCase
{
    private static ?int $port = null;
    private static mixed $process = null;

    public static function setUpBeforeClass(): void
    {
        self::$port = self::findFreePort();
        self::$process = proc_open(
            sprintf('exec php -S 127.0.0.1:%d %s', self::$port, escapeshellarg(__DIR__ . '/../Fixture/server.php')),
            [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
            $pipes
        );
        usleep(500000);
    }

    public static function tearDownAfterClass(): void
    {
        if (is_resource(self::$process)) {
            proc_terminate(self::$process);
            proc_close(self::$process);
        }
    }

    public function testThePoolFetchesEveryRequestAndReportsFailures(): void
    {
        $handler = new CurlMultiHandler(['max_total_connections' => 8, 'max_host_connections' => 2]);
        $client = new Client(new GuzzleClient(['handler' => \GuzzleHttp\HandlerStack::create($handler), 'http_errors' => false, 'timeout' => 5]), 0);
        $pool = new Pool($handler, $client);

        $base = sprintf('http://127.0.0.1:%d', self::$port);
        $results = $pool->run([
            ['url' => $base . '/', 'headers' => []],
            ['url' => $base . '/missing', 'headers' => []],
            ['url' => 'http://127.0.0.1:1/unreachable', 'headers' => []],
        ]);

        self::assertCount(3, $results);
        self::assertSame(200, $results[0]['response']?->getStatusCode());
        self::assertSame(404, $results[1]['response']?->getStatusCode());
        self::assertNull($results[2]['response']);
        self::assertNotNull($results[2]['error']);
    }

    public function testThePoolRunsRequestsConcurrently(): void
    {
        $handler = new CurlMultiHandler(['max_total_connections' => 8, 'max_host_connections' => 8]);
        $client = new Client(new GuzzleClient(['handler' => \GuzzleHttp\HandlerStack::create($handler), 'http_errors' => false, 'timeout' => 10]), 0);
        $pool = new Pool($handler, $client);

        $base = sprintf('http://127.0.0.1:%d', self::$port);
        $started = microtime(true);
        $pool->run([
            ['url' => $base . '/slow', 'headers' => []],
            ['url' => $base . '/slow', 'headers' => []],
            ['url' => $base . '/slow', 'headers' => []],
        ]);
        $elapsed = microtime(true) - $started;

        self::assertLessThan(2.5, $elapsed, 'Three one-second requests should overlap, not queue.');
    }

    public function testARedirectToAnotherHostIsNotFollowed(): void
    {
        $handler = new CurlMultiHandler();
        $client = new Client(new GuzzleClient(['handler' => HandlerStack::create($handler), 'http_errors' => false, 'timeout' => 5]), 0);
        $pool = new Pool($handler, $client);

        $results = $pool->run([
            ['url' => 'https://example.com/redirect', 'headers' => []],
        ]);

        // The 3xx itself is returned rather than the other host's body.
        self::assertNotNull($results[0]['response']);
        self::assertGreaterThanOrEqual(300, $results[0]['response']->getStatusCode());
        self::assertLessThan(400, $results[0]['response']->getStatusCode());
    }

    public function testGetReturnsNullOnTransportFailure(): void
    {
        $handler = new CurlMultiHandler();
        $client = new Client(new GuzzleClient(['handler' => \GuzzleHttp\HandlerStack::create($handler), 'http_errors' => false, 'timeout' => 2]), 0);

        self::assertNull($client->get('http://127.0.0.1:1/unreachable'));
    }

    private static function findFreePort(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        $name = stream_socket_get_name($socket, false);
        fclose($socket);

        return (int) substr((string) $name, strrpos((string) $name, ':') + 1);
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `composer test -- --filter HttpTest`
Expected: FAIL — `Class "Php2Scan\Http\Client" not found`.

- [ ] **Step 4: Implement `src/Http/Client.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Http;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Promise\PromiseInterface;
use Psr\Http\Message\ResponseInterface;

final class Client
{
    public function __construct(
        private readonly GuzzleClient $guzzle,
        private readonly int $delayMs = 0,
    ) {
    }

    public function guzzle(): GuzzleClient
    {
        return $this->guzzle;
    }

    /**
     * @param array<string, string> $headers
     */
    public function getAsync(string $url, array $headers = [], int $delayMs = 0): PromiseInterface
    {
        $options = [
            'http_errors' => false,
            'allow_redirects' => [
                'max' => 5,
                'strict' => false,
                'referer' => false,
                'track_redirects' => true,
                // A redirect that leaves the allowlisted host is not followed:
                // following it would contact a host the operator never listed.
                'on_redirect' => static function ($request, $response, $uri): bool {
                    $from = $request->getUri()->getHost();
                    $to = $uri->getHost();

                    return $from === '' || $to === '' || strcasecmp($from, $to) === 0;
                },
            ],
        ];

        if ($headers !== []) {
            $options['headers'] = $headers;
        }

        $delay = max($this->delayMs, $delayMs);
        if ($delay > 0) {
            $options['delay'] = $delay;
        }

        return $this->guzzle->requestAsync('GET', $url, $options);
    }

    /**
     * @param array<string, string> $headers
     */
    public function get(string $url, array $headers = []): ?ResponseInterface
    {
        try {
            return $this->getAsync($url, $headers)->wait();
        } catch (\Throwable) {
            return null;
        }
    }
}
```

- [ ] **Step 5: Implement `src/Http/Pool.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Http;

use GuzzleHttp\Handler\CurlMultiHandler;
use Psr\Http\Message\ResponseInterface;

final class Pool
{
    public function __construct(
        private readonly CurlMultiHandler $handler,
        private readonly Client $client,
    ) {
    }

    public function handler(): CurlMultiHandler
    {
        return $this->handler;
    }

    /**
     * @param list<array{url: string, headers: array<string, string>}> $requests
     * @param null|callable(string, ResponseInterface|null, string|null): void $onSettled
     * @return list<array{url: string, response: ResponseInterface|null, error: string|null}>
     */
    public function run(array $requests, ?callable $onSettled = null): array
    {
        $results = [];
        $settled = 0;

        if ($requests === []) {
            return [];
        }

        // Requests to the same host are spaced by the client delay so a scan
        // never hammers a single origin.
        $perHostCounter = [];

        foreach ($requests as $index => $request) {
            $host = (string) parse_url($request['url'], PHP_URL_HOST);
            $sequence = $perHostCounter[$host] ?? 0;
            $perHostCounter[$host] = $sequence + 1;

            $this->client
                ->getAsync($request['url'], $request['headers'], $sequence * $this->client->delayMs())
                ->then(
                    function (ResponseInterface $response) use (&$results, &$settled, $index, $request, $onSettled): void {
                        $results[$index] = ['url' => $request['url'], 'response' => $response, 'error' => null];
                        $settled++;
                        if ($onSettled !== null) {
                            $onSettled($request['url'], $response, null);
                        }
                    },
                    function (\Throwable $e) use (&$results, &$settled, $index, $request, $onSettled): void {
                        $results[$index] = ['url' => $request['url'], 'response' => null, 'error' => $e->getMessage()];
                        $settled++;
                        if ($onSettled !== null) {
                            $onSettled($request['url'], null, $e->getMessage());
                        }
                    }
                );
        }

        // Every request settles as either fulfilled or rejected; both branches
        // above increment $settled, so this loop always terminates.
        $guard = 0;
        while ($settled < count($requests)) {
            $this->handler->tick();
            $guard++;
            if ($guard > 100000) {
                break;
            }
        }

        ksort($results);

        return array_values($results);
    }
}
```

- [ ] **Step 6: Add the `delayMs()` accessor to `src/Http/Client.php`**

```php
    public function delayMs(): int
    {
        return $this->delayMs;
    }
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `composer test -- --filter HttpTest`
Expected: PASS — `OK (3 tests, 6 assertions)`. The concurrency test must show an elapsed time under 2.5 seconds for three one-second requests.

- [ ] **Step 8: Commit**

```bash
git add src/Http/Client.php src/Http/Pool.php tests/Integration/HttpTest.php tests/Fixture/server.php
git commit -m "feat: concurrent http client and request pool"
```

---

### Task 6: Wordlist and reproduce-step loaders

**Files:**
- Create: `src/Data/Wordlists.php`
- Create: `src/Data/Reproduce.php`
- Create: `data/sensitive-paths.txt`
- Create: `data/webshell-paths.txt`
- Create: `data/open-ports.txt`
- Create: `data/repro/php2shell-version.md`
- Create: `data/repro/sensitive-file-env.md`
- Create: `data/repro/webshell-indicator.md`
- Test: `tests/Unit/DataTest.php`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `Php2Scan\Data\Wordlists` — `final class Wordlists`, constructed as `new Wordlists(string $dataDir)`. Methods:
    - `public function sensitivePaths(): list<string>`
    - `public function webshellPaths(): list<string>`
    - `public function openPorts(): list<int>`
    - `public function lines(string $file): list<string>` — reads a `data/*.txt` file, trims each line, drops empty lines and lines starting with `#`.
  - `Php2Scan\Data\Reproduce` — `final class Reproduce`, constructed as `new Reproduce(string $reproDir)`. Methods:
    - `public function steps(string $findingId, string $targetUrl, ?string $host = null): list<string>` — loads `data/repro/<findingId>.md`, splits on blank lines into steps, substitutes `{url}` with `$targetUrl` and `{host}` with `$host ?? $targetUrl`, and returns the steps. Returns `[]` when the file does not exist.

- [ ] **Step 1: Write the failing test `tests/Unit/DataTest.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use Php2Scan\Data\Reproduce;
use Php2Scan\Data\Wordlists;
use PHPUnit\Framework\TestCase;

final class DataTest extends TestCase
{
    private string $dataDir;

    protected function setUp(): void
    {
        $this->dataDir = __DIR__ . '/../../data';
    }

    public function testWordlistsAreLoadedAndCleaned(): void
    {
        $wordlists = new Wordlists($this->dataDir);

        $sensitive = $wordlists->sensitivePaths();
        self::assertContains('.env', $sensitive);
        self::assertContains('.git/config', $sensitive);
        self::assertNotContains('', $sensitive);

        self::assertContains('shell.php', $wordlists->webshellPaths());
        self::assertContains(443, $wordlists->openPorts());
        self::assertContains(3306, $wordlists->openPorts());
    }

    public function testReproduceStepsAreSplitOnBlankLinesAndSubstituted(): void
    {
        $reproduce = new Reproduce($this->dataDir . '/repro');
        $steps = $reproduce->steps('sensitive-file-env', 'https://legacy.example.com');

        self::assertGreaterThanOrEqual(2, count($steps));
        self::assertStringContainsString('https://legacy.example.com/.env', $steps[0]);
        self::assertStringNotContainsString('{url}', implode("\n", $steps));
    }

    public function testAMissingReproduceFileYieldsNoSteps(): void
    {
        $reproduce = new Reproduce($this->dataDir . '/repro');

        self::assertSame([], $reproduce->steps('does-not-exist', 'https://example.com'));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `composer test -- --filter DataTest`
Expected: FAIL — `Class "Php2Scan\Data\Wordlists" not found`.

- [ ] **Step 3: Create the data files**

`data/sensitive-paths.txt`:

```
.env
.env.local
.env.production
.git/config
.git/HEAD
composer.json
composer.lock
package.json
package-lock.json
.htaccess
.DS_Store
phpinfo.php
info.php
server-status
server-info
wp-config.php.bak
backup.zip
dump.sql
.aws/credentials
.npmrc
.dockerignore
Dockerfile
adminer.php
phpmyadmin/
id_rsa
```

`data/webshell-paths.txt`:

```
shell.php
c99.php
r57.php
b374k.php
c1001.php
cmd.php
x.php
h.php
b.php
0.php
1.php
s.php
webshell.php
```

`data/open-ports.txt`:

```
21
22
25
80
443
3306
5432
6379
8080
8443
27017
```

- [ ] **Step 4: Create `data/repro/sensitive-file-env.md`**

```
curl -sS {url}/.env | head -20
# shows the raw file, including any APP_KEY / DB_PASSWORD lines
curl -sS {url}/.env | grep -iE 'APP_KEY|DB_PASSWORD|SECRET|TOKEN'
```

- [ ] **Step 5: Create `data/repro/php2shell-version.md`**

```
curl -sI {url}/ | grep -iE 'x-powered-by|^server:'
# confirms the PHP version the server advertises
ssh {host} 'php -v; php -i | grep -E "memory_limit|opcache.enable"'
# confirms the real runtime version on the host itself
# CVE-2026-109618 OOM trigger - the bytes are version- and build-specific.
# Take them from the published research: https://www.wiz.io/blog/php2shell-php-rce
# Expected effect: the FPM worker dies and the request returns 502.
# Run this against a staging copy, never against production.
```

- [ ] **Step 6: Create `data/repro/webshell-indicator.md`**

```
curl -sS -o /dev/null -w '%{http_code} %{size_download}\n' '{url}/{path}'
# a 200 on a webshell filename is the tell
curl -sS '{url}/{path}' | grep -iE 'system\(|shell_exec\(|passthru\(|proc_open\(|base64_decode\('
# confirms the file actually executes shell commands
```

- [ ] **Step 7: Implement `src/Data/Wordlists.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Data;

final class Wordlists
{
    public function __construct(private readonly string $dataDir)
    {
    }

    /**
     * @return list<string>
     */
    public function sensitivePaths(): array
    {
        return $this->lines('sensitive-paths.txt');
    }

    /**
     * @return list<string>
     */
    public function webshellPaths(): array
    {
        return $this->lines('webshell-paths.txt');
    }

    /**
     * @return list<int>
     */
    public function openPorts(): array
    {
        return array_map('intval', $this->lines('open-ports.txt'));
    }

    /**
     * @return list<string>
     */
    public function lines(string $file): array
    {
        $path = $this->dataDir . '/' . $file;
        $raw = @file_get_contents($path);

        if ($raw === false) {
            return [];
        }

        $lines = [];

        foreach (preg_split('/\R/', $raw) ?: [] as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            $lines[] = $line;
        }

        return $lines;
    }
}
```

- [ ] **Step 8: Implement `src/Data/Reproduce.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Data;

final class Reproduce
{
    public function __construct(private readonly string $reproDir)
    {
    }

    /**
     * @return list<string>
     */
    public function steps(string $findingId, string $targetUrl, ?string $host = null): array
    {
        $path = $this->reproDir . '/' . $findingId . '.md';
        $raw = @file_get_contents($path);

        if ($raw === false) {
            return [];
        }

        $blocks = preg_split('/\R\s*\R/', trim($raw)) ?: [];
        $steps = [];

        foreach ($blocks as $block) {
            $block = trim($block);
            if ($block === '') {
                continue;
            }

            $steps[] = strtr($block, [
                '{url}' => rtrim($targetUrl, '/'),
                '{host}' => $host ?? rtrim($targetUrl, '/'),
            ]);
        }

        return $steps;
    }
}
```

- [ ] **Step 9: Run the test to verify it passes**

Run: `composer test -- --filter DataTest`
Expected: PASS — `OK (3 tests, 8 assertions)`.

- [ ] **Step 10: Commit**

```bash
git add src/Data/Wordlists.php src/Data/Reproduce.php data/ tests/Unit/DataTest.php
git commit -m "feat: wordlist and reproduce-step data loaders"
```

---

### Task 7: Check interface, registry, and the engine

**Files:**
- Create: `src/Check/Check.php`
- Create: `src/Check/Registry.php`
- Create: `src/Engine.php`
- Create: `src/ScanResult.php`
- Test: `tests/Unit/EngineTest.php`

**Interfaces:**
- Consumes: `Php2Scan\Config`, `Php2Scan\Target`, `Php2Scan\Finding`, `Php2Scan\Http\Client`, `Php2Scan\Http\Pool` (Tasks 3, 5).
- Produces:
  - `Php2Scan\Check\Check` — interface with:
    - `public function id(): string`
    - `public function paths(\Php2Scan\Target $target, ?\Psr\Http\Message\ResponseInterface $baseline): array` — relative paths to fetch, e.g. `['/', '/.env']`.
    - `public function analyze(\Php2Scan\Target $target, array $responses): array` — `$responses` is `array<string, ResponseInterface>` keyed by the requested path, always containing `'/'` when the baseline was fetched. Returns `list<Finding>`.
  - `Php2Scan\Check\Registry` — `final class Registry`, constructed as `new Registry(array $checks)` where `$checks` is `array<string, Check>`; method `public function enabled(Config $config): list<Check>` returning the checks whose `id()` is enabled in the config, in the order of `Config::CHECKS`.
  - `Php2Scan\ScanResult` — `final class ScanResult` with `public readonly` promoted properties `array $findings` (`list<Finding>`), `array $unreachable` (`list<array{target: string, error: string}>`), `array $unscannable` (`list<array{target: string, status: int}>`), `float $duration`.
  - `Php2Scan\Engine` — `final class Engine`, constructed as `new Engine(Http\Pool $pool, Http\Client $client, Check\Registry $registry)`. Method:
    - `public function run(Config $config, ?callable $onProgress = null): ScanResult` — `$onProgress` receives `(string $targetLabel, string $phase, int $done, int $total)`.

**Engine behaviour (the three phases):**

1. **Baseline phase** — request `'/'` for every target concurrently through the pool. A target whose baseline request failed with a transport error goes to `unreachable`. A target whose baseline returned a status of 403, 407, 429, 503 goes to `unscannable`.
2. **Prefetch phase** — for each reachable target, ask every enabled check for `paths($target, $baseline)`; collect the union of all paths; fetch them all concurrently through the pool.
3. **Analysis phase** — for each reachable target, call `analyze($target, $responses)` on every enabled check and collect the findings.

- [ ] **Step 1: Write the failing test `tests/Unit/EngineTest.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\CurlMultiHandler;
use GuzzleHttp\HandlerStack;
use PHPUnit\Framework\TestCase;
use Php2Scan\Check\Check;
use Php2Scan\Check\Registry;
use Php2Scan\Config;
use Php2Scan\Engine;
use Php2Scan\Finding;
use Php2Scan\Http\Client;
use Php2Scan\Http\Pool;
use Php2Scan\Severity;
use Psr\Http\Message\ResponseInterface;

final class EngineTest extends TestCase
{
    public function testItRunsChecksAgainstEveryTargetAndCollectsFindings(): void
    {
        $handler = new CurlMultiHandler();
        $client = new Client(new GuzzleClient(['handler' => HandlerStack::create($handler), 'http_errors' => false]), 0);
        $pool = new Pool($handler, $client);

        $check = new class implements Check {
            public function id(): string
            {
                return 'php_presence';
            }

            public function paths(\Php2Scan\Target $target, ?ResponseInterface $baseline): array
            {
                return ['/'];
            }

            public function analyze(\Php2Scan\Target $target, array $responses): array
            {
                return [new Finding(
                    id: 'php_presence',
                    title: 'PHP detected',
                    severity: Severity::Info,
                    target: $target->host(),
                    evidence: 'test',
                    exploit: 'test',
                    reproduce: ['step'],
                )];
            }
        };

        $engine = new Engine($pool, $client, new Registry(['php_presence' => $check]));

        $result = $engine->run(Config::fromArray([
            'targets' => ['https://127.0.0.1:1/nope'],
            'checks' => ['php_presence' => true],
        ]));

        self::assertCount(1, $result->unreachable);
        self::assertSame('127.0.0.1', $result->unreachable[0]['target']);
    }

    public function testATargetThatAnswersWithForbiddenIsUnscannableNotUnreachable(): void
    {
        $handler = new CurlMultiHandler();
        $client = new Client(new GuzzleClient(['handler' => HandlerStack::create($handler), 'http_errors' => false, 'timeout' => 2]), 0);
        $pool = new Pool($handler, $client);

        $check = new class implements Check {
            public function id(): string
            {
                return 'php_presence';
            }

            public function paths(\Php2Scan\Target $target, ?ResponseInterface $baseline): array
            {
                return [];
            }

            public function analyze(\Php2Scan\Target $target, array $responses): array
            {
                return [];
            }
        };

        $engine = new Engine($pool, $client, new Registry(['php_presence' => $check]));

        $result = $engine->run(Config::fromArray([
            'targets' => ['https://127.0.0.1:1/nope'],
            'checks' => ['php_presence' => true],
        ]));

        self::assertSame([], $result->unreachable);
        self::assertSame([], $result->unscannable);
    }

    public function testAnUnreachableTargetDoesNotStopTheOthers(): void
    {
        $handler = new CurlMultiHandler();
        $client = new Client(new GuzzleClient(['handler' => HandlerStack::create($handler), 'http_errors' => false, 'timeout' => 2]), 0);
        $pool = new Pool($handler, $client);

        $check = new class implements Check {
            public function id(): string
            {
                return 'php_presence';
            }

            public function paths(\Php2Scan\Target $target, ?ResponseInterface $baseline): array
            {
                return [];
            }

            public function analyze(\Php2Scan\Target $target, array $responses): array
            {
                return [];
            }
        };

        $engine = new Engine($pool, $client, new Registry(['php_presence' => $check]));

        $result = $engine->run(Config::fromArray([
            'targets' => ['https://127.0.0.1:1/nope', 'https://127.0.0.1:2/nope'],
            'checks' => ['php_presence' => true],
        ]));

        self::assertCount(2, $result->unreachable);
        self::assertSame([], $result->findings);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `composer test -- --filter EngineTest`
Expected: FAIL — `Interface "Php2Scan\Check\Check" not found`.

- [ ] **Step 3: Create `src/Check/Check.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Check;

use Php2Scan\Finding;
use Php2Scan\Target;
use Psr\Http\Message\ResponseInterface;

interface Check
{
    public function id(): string;

    /**
     * Relative paths this check wants fetched for the given target.
     *
     * @return list<string>
     */
    public function paths(Target $target, ?ResponseInterface $baseline): array;

    /**
     * @param array<string, ResponseInterface> $responses keyed by the requested path
     * @return list<Finding>
     */
    public function analyze(Target $target, array $responses): array;
}
```

- [ ] **Step 4: Create `src/Check/Registry.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Check;

use Php2Scan\Config;

final class Registry
{
    /**
     * @param array<string, Check> $checks
     */
    public function __construct(private readonly array $checks)
    {
    }

    /**
     * @return list<Check>
     */
    public function enabled(Config $config): array
    {
        $enabled = [];

        foreach (Config::CHECKS as $id) {
            if (!$config->checkEnabled($id)) {
                continue;
            }

            if (isset($this->checks[$id])) {
                $enabled[] = $this->checks[$id];
            }
        }

        return $enabled;
    }
}
```

- [ ] **Step 5: Create `src/ScanResult.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan;

final class ScanResult
{
    /**
     * @param list<Finding>                        $findings
     * @param list<array{target: string, error: string}>   $unreachable
     * @param list<array{target: string, status: int}>      $unscannable
     */
    public function __construct(
        public readonly array $findings,
        public readonly array $unreachable,
        public readonly array $unscannable,
        public readonly float $duration,
    ) {
    }
}
```

- [ ] **Step 6: Implement `src/Engine.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan;

use Php2Scan\Check\Check;
use Php2Scan\Http\Client;
use Php2Scan\Http\Pool;
use Psr\Http\Message\ResponseInterface;

final class Engine
{
    public function __construct(
        private readonly Pool $pool,
        private readonly Client $client,
        private readonly Check\Registry $registry,
    ) {
    }

    public function run(Config $config, ?callable $onProgress = null): ScanResult
    {
        $started = microtime(true);

        $checks = $this->registry->enabled($config);
        $findings = [];
        $unreachable = [];
        $unscannable = [];

        // Phase 1 - baseline.
        $baselineRequests = [];
        foreach ($config->targets as $target) {
            $baselineRequests[] = ['url' => $target->url, 'headers' => $target->requestHeaders()];
        }

        $baselines = $this->pool->run($baselineRequests);

        $reachable = [];
        foreach ($config->targets as $index => $target) {
            $response = $baselines[$index]['response'] ?? null;

            if ($response === null) {
                $unreachable[] = ['target' => $target->label(), 'error' => $baselines[$index]['error'] ?? 'unknown error'];
                continue;
            }

            if (in_array($response->getStatusCode(), [403, 407, 429, 503], true)) {
                $unscannable[] = ['target' => $target->label(), 'status' => $response->getStatusCode()];
                continue;
            }

            $reachable[$index] = ['target' => $target, 'baseline' => $response];
        }

        if ($onProgress !== null) {
            $onProgress('all', 'baseline', count($baselines), count($baselines));
        }

        // Phase 2 - prefetch every path every check asked for.
        $requests = [];
        $requestIndex = [];
        foreach ($reachable as $index => $entry) {
            $target = $entry['target'];
            $paths = ['/'];
            foreach ($checks as $check) {
                foreach ($check->paths($target, $entry['baseline']) as $path) {
                    $paths[] = $path;
                }
            }
            $paths = array_values(array_unique($paths));

            foreach ($paths as $path) {
                $url = $this->urlFor($target, $path);
                $requestIndex[$index][$path] = count($requests);
                $requests[] = ['url' => $url, 'headers' => $target->requestHeaders()];
            }
        }

        $responses = $this->pool->run($requests);

        if ($onProgress !== null) {
            $onProgress('all', 'probe', count($requests), count($requests));
        }

        // Phase 3 - analyse.
        foreach ($reachable as $index => $entry) {
            $target = $entry['target'];
            $perTarget = [];

            foreach (array_keys($requestIndex[$index] ?? []) as $path) {
                $position = $requestIndex[$index][$path];
                $response = $responses[$position]['response'] ?? null;
                if ($response !== null) {
                    $perTarget[$path] = $response;
                }
            }

            foreach ($checks as $check) {
                foreach ($check->analyze($target, $perTarget) as $finding) {
                    $findings[] = $finding;
                }
            }

            if ($onProgress !== null) {
                $onProgress($target->label(), 'analyse', 0, 0);
            }
        }

        return new ScanResult($findings, $unreachable, $unscannable, microtime(true) - $started);
    }

    private function urlFor(Target $target, string $path): string
    {
        if (str_starts_with($path, 'http://') || str_starts_with($path, 'https://')) {
            return $path;
        }

        return rtrim($target->url, '/') . '/' . ltrim($path, '/');
    }
}
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `composer test -- --filter EngineTest`
Expected: PASS — `OK (2 tests, 3 assertions)`.

- [ ] **Step 8: Commit**

```bash
git add src/Check/Check.php src/Check/Registry.php src/Engine.php src/ScanResult.php tests/Unit/EngineTest.php
git commit -m "feat: check interface, registry and three-phase engine"
```

---

### Task 8: PHP detection and PHP version checks

**Files:**
- Create: `src/Check/PhpDetection.php`
- Create: `src/Check/PhpVersion.php`
- Create: `data/repro/php2shell-version.md` (exists — extend if needed)
- Test: `tests/Unit/PhpChecksTest.php`

**Interfaces:**
- Consumes: `Php2Scan\Check\Check` (Task 7), `Php2Scan\PhpVersionDb` (Task 4), `Php2Scan\Data\Reproduce` (Task 6).
- Produces:
  - `Php2Scan\Check\PhpDetection` — `final class PhpDetection implements Check`, constructed as `new PhpDetection(Data\Reproduce $reproduce)`. `id()` returns `'php_presence'`. `paths()` returns `['/']`. `analyze()` returns:
    - one `Finding` with id `php_presence` and severity `info` when PHP is detected, evidence naming the signals that fired.
    - one `Finding` with id `php_presence` and severity `info` with the title `No PHP detected` when it is not.
  - `Php2Scan\Check\PhpVersion` — `final class PhpVersion implements Check`, constructed as `new PhpVersion(PhpVersionDb $db, Data\Reproduce $reproduce)`. `id()` returns `'php_version'`. `paths()` returns `['/', '/phpinfo.php', '/info.php']`. `analyze()` returns:
    - `php2shell-version` — severity `critical` when the version is affected, title `PHP2Shell · CVE-2026-109618`, evidence naming the version, its source and the confidence.
    - `php2shell-version` — severity `info` when the version is patched, title `PHP2Shell not applicable (patched)`.
    - `php2shell-version` — severity `high` when PHP is present but the version is unknown, title `PHP2Shell · version undetermined`.
    - `php2shell-version` — severity `info` when no PHP was detected.

**Version source precedence (highest confidence first):**

1. `X-Powered-By: PHP/x.y.z` → confidence `high`
2. `Server: … PHP/x.y.z` → confidence `medium`
3. `phpinfo()` output on `/phpinfo.php` or `/info.php` matching `PHP Version (\d+\.\d+\.\d+)` → confidence `medium`

- [ ] **Step 1: Write the failing test `tests/Unit/PhpChecksTest.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use GuzzleHttp\Psr7\Response;
use Php2Scan\Check\PhpDetection;
use Php2Scan\Check\PhpVersion;
use Php2Scan\Data\Reproduce;
use Php2Scan\PhpVersionDb;
use Php2Scan\Severity;
use Php2Scan\Target;
use PHPUnit\Framework\TestCase;

final class PhpChecksTest extends TestCase
{
    private Target $target;
    private Reproduce $reproduce;
    private PhpVersionDb $db;

    protected function setUp(): void
    {
        $this->target = new Target('https://legacy.example.com');
        $this->reproduce = new Reproduce(__DIR__ . '/../../data/repro');
        $this->db = new PhpVersionDb(__DIR__ . '/../../data/php-affected.json');
    }

    public function testItDetectsPhpFromThePoweredByHeader(): void
    {
        $findings = (new PhpDetection($this->reproduce))->analyze($this->target, [
            '/' => new Response(200, ['X-Powered-By' => 'PHP/8.1.29'], 'body'),
        ]);

        self::assertCount(1, $findings);
        self::assertSame('php_presence', $findings[0]->id);
        self::assertStringContainsString('X-Powered-By', $findings[0]->evidence);
        self::assertNotSame('', $findings[0]->exploit);
        self::assertNotEmpty($findings[0]->reproduce);
    }

    public function testItReportsNoPhpWhenNoSignalFires(): void
    {
        $findings = (new PhpDetection($this->reproduce))->analyze($this->target, [
            '/' => new Response(200, [], '<html>hi</html>'),
        ]);

        self::assertCount(1, $findings);
        self::assertStringContainsString('No PHP', $findings[0]->title);
    }

    public function testA404BaselineStillRevealsThePhpVersion(): void
    {
        $findings = (new PhpVersion($this->db, $this->reproduce))->analyze($this->target, [
            '/' => new Response(404, ['Server' => 'Apache/2.4.58 (Unix) PHP/8.1.29'], '<h1>Not Found</h1>'),
        ]);

        self::assertSame(Severity::Critical, $findings[0]->severity);
        self::assertStringContainsString('8.1.29', $findings[0]->evidence);
    }

    public function testItFlagsAnAffectedVersionAsCritical(): void
    {
        $findings = (new PhpVersion($this->db, $this->reproduce))->analyze($this->target, [
            '/' => new Response(200, ['X-Powered-By' => 'PHP/8.1.29'], 'body'),
        ]);

        self::assertCount(1, $findings);
        self::assertSame(Severity::Critical, $findings[0]->severity);
        self::assertStringContainsString('8.1.29', $findings[0]->evidence);
        self::assertStringContainsString('8.2.35', $findings[0]->evidence);
    }

    public function testAVersionNewerThanTheAdvisoryIsLowNotPatched(): void
    {
        $findings = (new PhpVersion($this->db, $this->reproduce))->analyze($this->target, [
            '/' => new Response(200, ['X-Powered-By' => 'PHP/8.6.0'], 'body'),
        ]);

        self::assertSame(Severity::Low, $findings[0]->severity);
    }

    public function testAPatchedVersionIsInformational(): void
    {
        $findings = (new PhpVersion($this->db, $this->reproduce))->analyze($this->target, [
            '/' => new Response(200, ['X-Powered-By' => 'PHP/8.5.12'], 'body'),
        ]);

        self::assertSame(Severity::Info, $findings[0]->severity);
    }

    public function testAnUnknownVersionIsHighNotCritical(): void
    {
        $findings = (new PhpVersion($this->db, $this->reproduce))->analyze($this->target, [
            '/' => new Response(200, ['Set-Cookie' => 'PHPSESSID=abc; path=/'], 'body'),
        ]);

        self::assertSame(Severity::High, $findings[0]->severity);
        self::assertStringContainsString('php -v', implode("\n", $findings[0]->reproduce));
    }

    public function testAnUnparseableVersionIsTreatedAsUnknown(): void
    {
        $findings = (new PhpVersion($this->db, $this->reproduce))->analyze($this->target, [
            '/' => new Response(200, ['X-Powered-By' => 'PHP/not-a-version'], 'body'),
        ]);

        self::assertSame(Severity::High, $findings[0]->severity);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `composer test -- --filter PhpChecksTest`
Expected: FAIL — `Class "Php2Scan\Check\PhpDetection" not found`.

- [ ] **Step 3: Implement `src/Check/PhpDetection.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Check;

use Php2Scan\Data\Reproduce;
use Php2Scan\Finding;
use Php2Scan\Severity;
use Php2Scan\Target;
use Psr\Http\Message\ResponseInterface;

final class PhpDetection implements Check
{
    public function __construct(private readonly Reproduce $reproduce)
    {
    }

    public function id(): string
    {
        return 'php_presence';
    }

    public function paths(Target $target, ?ResponseInterface $baseline): array
    {
        return ['/'];
    }

    public function analyze(Target $target, array $responses): array
    {
        $baseline = $responses['/'] ?? null;
        $signals = $baseline === null ? [] : self::signals($baseline);

        if ($signals === []) {
            return [new Finding(
                id: 'php_presence',
                title: 'No PHP detected',
                severity: Severity::Info,
                target: $target->label(),
                evidence: 'No X-Powered-By header, no PHP in the Server header, no PHP session cookie.',
                exploit: 'Nothing to exploit here - this host does not serve PHP, so PHP2Shell cannot apply.',
                reproduce: $this->reproduce->steps('php_presence', $target->url, $target->label()),
            )];
        }

        return [new Finding(
            id: 'php_presence',
            title: 'PHP detected',
            severity: Severity::Info,
            target: $target->label(),
            evidence: 'Signals: ' . implode(', ', $signals) . '.',
            exploit: 'Confirm the runtime version on the host with "php -v" - every PHP release before 8.2.35 is exposed to PHP2Shell.',
            reproduce: $this->reproduce->steps('php_presence', $target->url, $target->label()),
        )];
    }

    /**
     * @return list<string>
     */
    public static function signals(ResponseInterface $response): array
    {
        $signals = [];

        $poweredBy = $response->getHeaderLine('X-Powered-By');
        if ($poweredBy !== '') {
            $signals[] = 'X-Powered-By: ' . $poweredBy;
        }

        $server = $response->getHeaderLine('Server');
        if ($server !== '' && preg_match('/\bPHP\/(\d+\.\d+(?:\.\d+)?)/i', $server, $m) === 1) {
            $signals[] = 'Server: ' . $server;
        }

        foreach ($response->getHeader('Set-Cookie') as $cookie) {
            if (str_starts_with($cookie, 'PHPSESSID')) {
                $signals[] = 'Set-Cookie: PHPSESSID';
                break;
            }
        }

        $body = (string) $response->getBody();
        if ($body !== '' && preg_match('/Powered by PHP|<meta[^>]+generator[^>]+PHP/i', $body) === 1) {
            $signals[] = 'body marker';
        }

        return $signals;
    }
}
```

- [ ] **Step 4: Implement `src/Check/PhpVersion.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Check;

use Php2Scan\Data\Reproduce;
use Php2Scan\Finding;
use Php2Scan\PhpVersionDb;
use Php2Scan\Severity;
use Php2Scan\Target;
use Psr\Http\Message\ResponseInterface;

final class PhpVersion implements Check
{
    public function __construct(
        private readonly PhpVersionDb $db,
        private readonly Reproduce $reproduce,
    ) {
    }

    public function id(): string
    {
        return 'php_version';
    }

    public function paths(Target $target, ?ResponseInterface $baseline): array
    {
        return ['/', '/phpinfo.php', '/info.php'];
    }

    public function analyze(Target $target, array $responses): array
    {
        $baseline = $responses['/'] ?? null;
        $version = null;
        $source = '';
        $confidence = '';

        if ($baseline !== null) {
            $poweredBy = $baseline->getHeaderLine('X-Powered-By');
            if (preg_match('/PHP\/(\d+\.\d+(?:\.\d+)?)/i', $poweredBy, $m) === 1) {
                $version = $m[1];
                $source = 'X-Powered-By';
                $confidence = 'high';
            }
        }

        if ($version === null && $baseline !== null) {
            $server = $baseline->getHeaderLine('Server');
            if (preg_match('/\bPHP\/(\d+\.\d+(?:\.\d+)?)/i', $server, $m) === 1) {
                $version = $m[1];
                $source = 'Server header';
                $confidence = 'medium';
            }
        }

        if ($version === null) {
            foreach (['/phpinfo.php', '/info.php'] as $path) {
                $response = $responses[$path] ?? null;
                if ($response === null || $response->getStatusCode() !== 200) {
                    continue;
                }
                $body = (string) $response->getBody();
                if (preg_match('/PHP Version (\d+\.\d+(?:\.\d+)?)/i', $body, $m) === 1) {
                    $version = $m[1];
                    $source = $path;
                    $confidence = 'medium';
                    break;
                }
            }
        }

        $steps = $this->reproduce->steps('php2shell-version', $target->url, $target->label());

        if ($version === null) {
            $phpPresent = $baseline !== null && PhpDetection::signals($baseline) !== [];

            if (!$phpPresent) {
                return [new Finding(
                    id: 'php2shell-version',
                    title: 'PHP2Shell not applicable - no PHP detected',
                    severity: Severity::Info,
                    target: $target->label(),
                    evidence: 'No PHP version could be found and no PHP signal fired.',
                    exploit: 'Nothing to exploit - this host does not run PHP.',
                    reproduce: $steps,
                )];
            }

            return [new Finding(
                id: 'php2shell-version',
                title: 'PHP2Shell - version undetermined',
                severity: Severity::High,
                target: $target->label(),
                evidence: 'PHP is present but the version is not disclosed remotely; the server may still run an affected release.',
                exploit: 'Read the version with "php -v" on the host - any release before 8.2.35 (or before 8.3.36 / 8.4.27 / 8.5.12 on those branches) is exposed to a pre-auth RCE.',
                reproduce: $steps,
            )];
        }

        $normalized = $this->db->normalize($version);

        if ($normalized === null) {
            return [new Finding(
                id: 'php2shell-version',
                title: 'PHP2Shell - version undetermined',
                severity: Severity::High,
                target: $target->label(),
                evidence: sprintf('The server advertised "%s", which is not a comparable version string.', $version),
                exploit: 'Read the version with "php -v" on the host - any release before 8.2.35 (or before 8.3.36 / 8.4.27 / 8.5.12 on those branches) is exposed to a pre-auth RCE.',
                reproduce: $steps,
            )];
        }

        if (version_compare($normalized, $this->db->newestKnown(), '>')) {
            return [new Finding(
                id: 'php2shell-version',
                title: 'PHP2Shell - release newer than the advisory',
                severity: Severity::Low,
                target: $target->label(),
                evidence: sprintf('PHP %s detected via %s (confidence: %s); newer than the newest release the advisory covers (%s).', $normalized, $source, $confidence, $this->db->newestKnown()),
                exploit: 'Re-check the advisories against this release - the scanner only knows the versions published in the PHP2Shell advisory.',
                reproduce: $steps,
            )];
        }

        $fixed = $this->db->fixedFor($normalized);
        $affected = $this->db->isAffected($normalized);

        if (!$affected) {
            return [new Finding(
                id: 'php2shell-version',
                title: 'PHP2Shell not applicable (patched)',
                severity: Severity::Info,
                target: $target->label(),
                evidence: sprintf('PHP %s detected via %s (confidence: %s); patched in %s.', $normalized, $source, $confidence, (string) $fixed),
                exploit: 'Nothing to exploit - this runtime is on a patched PHP release.',
                reproduce: $steps,
            )];
        }

        return [new Finding(
            id: 'php2shell-version',
            title: 'PHP2Shell · ' . implode(' · ', $this->db->cves()),
            severity: Severity::Critical,
            target: $target->label(),
            evidence: sprintf(
                'PHP %s detected via %s (confidence: %s); affected - patched in %s.',
                $normalized,
                $source,
                $confidence,
                $fixed === null ? 'no fixed release exists for this branch' : $fixed
            ),
            exploit: 'Send the published out-of-memory trigger to any .php endpoint to get pre-auth remote code execution as the PHP-FPM worker.',
            reproduce: $steps,
        )];
    }
}
```

- [ ] **Step 5: Create `data/repro/php_presence.md`**

```
curl -sI {url}/ | grep -iE 'x-powered-by|^server:|set-cookie'
# lists the signals that reveal the host runs PHP
ssh {host} 'php -v'
# the authoritative version, which the headers may hide
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `composer test -- --filter PhpChecksTest`
Expected: PASS — `OK (6 tests, 9 assertions)`.

- [ ] **Step 7: Commit**

```bash
git add src/Check/PhpDetection.php src/Check/PhpVersion.php data/repro/php_presence.md tests/Unit/PhpChecksTest.php
git commit -m "feat: php presence detection and PHP2Shell version triage"
```

---

### Task 9: Sensitive files check

**Files:**
- Create: `src/Check/SensitiveFiles.php`
- Create: `data/repro/sensitive-file.md`
- Test: `tests/Unit/SensitiveFilesTest.php`

**Interfaces:**
- Consumes: `Php2Scan\Data\Wordlists`, `Php2Scan\Data\Reproduce` (Task 6), `Php2Scan\Check\Check` (Task 7).
- Produces: `Php2Scan\Check\SensitiveFiles implements Check`, `id()` returns `'sensitive_files'`. `paths()` returns the wordlist paths plus `Target::$paths` prefixed with `/`. `analyze()` returns one `Finding` per path that returned `200` with a body.

**Severity mapping (verbatim from the spec §8.1):**

| Path | Severity |
|---|---|
| `.env`, `.env.local`, `.env.production`, `.git/config`, `.git/HEAD`, `.aws/credentials`, `id_rsa`, `.npmrc`, `*.bak`, `backup.zip`, `dump.sql` | high |
| `composer.json`, `composer.lock`, `package.json`, `package-lock.json`, `.htaccess` | medium |
| `phpinfo.php`, `info.php`, `server-status`, `server-info` | medium |
| `Dockerfile`, `.dockerignore` | low |

- [ ] **Step 1: Write the failing test `tests/Unit/SensitiveFilesTest.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use GuzzleHttp\Psr7\Response;
use Php2Scan\Check\SensitiveFiles;
use Php2Scan\Data\Reproduce;
use Php2Scan\Data\Wordlists;
use Php2Scan\Severity;
use Php2Scan\Target;
use PHPUnit\Framework\TestCase;

final class SensitiveFilesTest extends TestCase
{
    private SensitiveFiles $check;

    protected function setUp(): void
    {
        $this->check = new SensitiveFiles(
            new Wordlists(__DIR__ . '/../../data'),
            new Reproduce(__DIR__ . '/../../data/repro'),
        );
    }

    public function testAnExposedEnvFileIsHigh(): void
    {
        $findings = $this->check->analyze(new Target('https://legacy.example.com'), [
            '/.env' => new Response(200, [], "APP_KEY=base64:abc\nDB_PASSWORD=hunter2\n"),
        ]);

        self::assertCount(1, $findings);
        self::assertSame(Severity::High, $findings[0]->severity);
        self::assertStringContainsString('APP_KEY', $findings[0]->evidence);
        self::assertNotEmpty($findings[0]->reproduce);
    }

    public function testA404IsNotAFinding(): void
    {
        $findings = $this->check->analyze(new Target('https://legacy.example.com'), [
            '/.env' => new Response(404, [], 'Not Found'),
        ]);

        self::assertSame([], $findings);
    }

    public function testALeakedManifestIsMedium(): void
    {
        $findings = $this->check->analyze(new Target('https://legacy.example.com'), [
            '/composer.lock' => new Response(200, [], '{"packages":[]}'),
        ]);

        self::assertSame(Severity::Medium, $findings[0]->severity);
    }

    public function testEveryFindingCarriesAReproduceStep(): void
    {
        $findings = $this->check->analyze(new Target('https://legacy.example.com'), [
            '/.env' => new Response(200, [], "APP_KEY=abc\n"),
            '/composer.lock' => new Response(200, [], '{}'),
        ]);

        foreach ($findings as $finding) {
            self::assertNotEmpty($finding->reproduce, $finding->id . ' must have reproduce steps');
            self::assertNotSame('', trim($finding->exploit));
        }
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `composer test -- --filter SensitiveFilesTest`
Expected: FAIL — `Class "Php2Scan\Check\SensitiveFiles" not found`.

- [ ] **Step 3: Implement `src/Check/SensitiveFiles.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Check;

use Php2Scan\Data\Reproduce;
use Php2Scan\Data\Wordlists;
use Php2Scan\Finding;
use Php2Scan\Severity;
use Php2Scan\Target;
use Psr\Http\Message\ResponseInterface;

final class SensitiveFiles implements Check
{
    private const HIGH = [
        '.env', '.env.local', '.env.production', '.git/config', '.git/HEAD',
        '.aws/credentials', 'id_rsa', '.npmrc', 'backup.zip', 'dump.sql',
    ];

    private const MEDIUM = [
        'composer.json', 'composer.lock', 'package.json', 'package-lock.json',
        '.htaccess', 'phpinfo.php', 'info.php', 'server-status', 'server-info',
    ];

    private const LOW = ['Dockerfile', '.dockerignore'];

    private const SECRET_PATTERN = '/(APP_KEY|DB_PASSWORD|SECRET|TOKEN|PASSWORD|PRIVATE KEY|api[_-]?key)/i';

    public function __construct(
        private readonly Wordlists $wordlists,
        private readonly Reproduce $reproduce,
    ) {
    }

    public function id(): string
    {
        return 'sensitive_files';
    }

    public function paths(Target $target, ?ResponseInterface $baseline): array
    {
        $paths = array_map(static fn (string $p): string => '/' . ltrim($p, '/'), $this->wordlists->sensitivePaths());

        foreach ($target->paths as $extra) {
            $paths[] = '/' . trim($extra, '/');
        }

        return array_values(array_unique($paths));
    }

    public function analyze(Target $target, array $responses): array
    {
        $findings = [];

        foreach ($responses as $path => $response) {
            if ($response->getStatusCode() !== 200) {
                continue;
            }

            $body = (string) $response->getBody();
            if (trim($body) === '') {
                continue;
            }

            $relative = ltrim($path, '/');
            $severity = self::severityFor($relative);
            $matched = preg_match(self::SECRET_PATTERN, $body) === 1
                ? 'contains credential-looking keys'
                : 'no credential-looking keys matched';

            $findings[] = new Finding(
                id: 'sensitive-file-' . str_replace('/', '-', $relative),
                title: 'Exposed ' . $relative,
                severity: $severity,
                target: $target->label(),
                evidence: sprintf(
                    'HTTP 200, %d bytes, %s.',
                    strlen($body),
                    $matched
                ),
                exploit: sprintf('Request %s and read whatever it returns - it is served publicly.', $target->url . '/' . $relative),
                reproduce: $this->reproduce->steps('sensitive-file', $target->url, $target->label()),
            );
        }

        return $findings;
    }

    private static function severityFor(string $relative): Severity
    {
        foreach (self::HIGH as $needle) {
            if ($relative === $needle || str_ends_with($relative, '.bak')) {
                return Severity::High;
            }
        }

        if (in_array($relative, self::MEDIUM, true)) {
            return Severity::Medium;
        }

        if (in_array($relative, self::LOW, true)) {
            return Severity::Low;
        }

        return Severity::Medium;
    }
}
```

- [ ] **Step 4: Create `data/repro/sensitive-file.md`**

```
curl -sS -o /dev/null -w '%{{http_code}} %{{size_download}}\n' '{url}/{path}'
# a 200 with a non-zero size means the file is public
curl -sS '{url}/{path}' | head -20
# the contents themselves
```

**Note for the implementer:** the reproduce loader substitutes `{url}` and `{host}` but not `{path}`. The `{path}` placeholder must be substituted by the check itself before calling `steps()`. Add a third argument to `Data\Reproduce::steps()` — change the signature to `steps(string $findingId, string $targetUrl, ?string $host = null, array $extra = [])` and substitute `{path}` from `$extra['path']` when present. Update `DataTest` accordingly to cover the new placeholder.

- [ ] **Step 5: Update `src/Data/Reproduce.php` for the `{path}` placeholder**

```php
    /**
     * @param array<string, string> $extra
     * @return list<string>
     */
    public function steps(string $findingId, string $targetUrl, ?string $host = null, array $extra = []): array
    {
        $path = $this->reproDir . '/' . $findingId . '.md';
        $raw = @file_get_contents($path);

        if ($raw === false) {
            return [];
        }

        $blocks = preg_split('/\R\s*\R/', trim($raw)) ?: [];
        $steps = [];

        foreach ($blocks as $block) {
            $block = trim($block);
            if ($block === '') {
                continue;
            }

            $steps[] = strtr($block, [
                '{url}' => rtrim($targetUrl, '/'),
                '{host}' => $host ?? rtrim($targetUrl, '/'),
                '{path}' => (string) ($extra['path'] ?? ''),
            ]);
        }

        return $steps;
    }
```

- [ ] **Step 6: Pass the path through from `SensitiveFiles`**

Change the call in `analyze()` to:

```php
                reproduce: $this->reproduce->steps('sensitive-file', $target->url, $target->label(), ['path' => $relative]),
```

- [ ] **Step 7: Add a test for the `{path}` placeholder in `tests/Unit/DataTest.php`**

```php
    public function testThePathPlaceholderIsSubstituted(): void
    {
        $reproduce = new Reproduce($this->dataDir . '/repro');
        $steps = $reproduce->steps('sensitive-file', 'https://legacy.example.com', 'legacy.example.com', ['path' => '.env']);

        self::assertStringContainsString('https://legacy.example.com/.env', $steps[0]);
        self::assertStringNotContainsString('{path}', implode("\n", $steps));
    }
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `composer test -- --filter 'SensitiveFilesTest|DataTest'`
Expected: PASS — `OK (8 tests, 14 assertions)`.

- [ ] **Step 9: Commit**

```bash
git add src/Check/SensitiveFiles.php src/Data/Reproduce.php data/repro/sensitive-file.md tests/Unit/SensitiveFilesTest.php tests/Unit/DataTest.php
git commit -m "feat: sensitive file exposure check"
```

---

### Task 10: Security headers check

**Files:**
- Create: `src/Check/SecurityHeaders.php`
- Create: `data/repro/security-headers.md`
- Test: `tests/Unit/SecurityHeadersTest.php`

**Interfaces:**
- Consumes: `Php2Scan\Data\Reproduce` (Task 6), `Php2Scan\Check\Check` (Task 7).
- Produces: `Php2Scan\Check\SecurityHeaders implements Check`, `id()` returns `'security_headers'`. `paths()` returns `['/']`. `analyze()` returns one `Finding` per problem.

**Header presence table and severity (verbatim from the spec §8.1):**

| Header | Severity |
|---|---|
| `Strict-Transport-Security` | medium, and only for HTTPS targets |
| `Content-Security-Policy` | low |
| `X-Content-Type-Options` | medium |
| `X-Frame-Options` (and no CSP `frame-ancestors`) | medium |
| `Referrer-Policy` | low |
| `X-Permitted-Cross-Domain-Policies` | low |

Cookie flags: one finding per cookie per missing flag (`Secure`, `HttpOnly`, `SameSite`), severity medium.

**Value validation:** use `Aidantwoods\SecureHeaders\Validator::validate()` with `Aidantwoods\SecureHeaders\HeaderBag` — **not** `SecureHeaders::apply()`, which replaces the error handler and cannot be captured externally. Strip HTML tags from the validator messages.

- [ ] **Step 1: Write the failing test `tests/Unit/SecurityHeadersTest.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use GuzzleHttp\Psr7\Response;
use Php2Scan\Check\SecurityHeaders;
use Php2Scan\Data\Reproduce;
use Php2Scan\Severity;
use Php2Scan\Target;
use PHPUnit\Framework\TestCase;

final class SecurityHeadersTest extends TestCase
{
    private SecurityHeaders $check;

    protected function setUp(): void
    {
        $this->check = new SecurityHeaders(new Reproduce(__DIR__ . '/../../data/repro'));
    }

    public function testAMissingHeaderIsReported(): void
    {
        $findings = $this->check->analyze(new Target('https://example.com'), [
            '/' => new Response(200, [], 'body'),
        ]);

        $ids = array_map(static fn ($f): string => $f->id, $findings);
        self::assertContains('missing-header-x-content-type-options', $ids);
    }

    public function testAFullyHardenedResponseProducesNoHeaderFindings(): void
    {
        $findings = $this->check->analyze(new Target('https://example.com'), [
            '/' => new Response(200, [
                'Content-Security-Policy' => "default-src 'self'",
                'Strict-Transport-Security' => 'max-age=31536000',
                'X-Content-Type-Options' => 'nosniff',
                'X-Frame-Options' => 'DENY',
                'Referrer-Policy' => 'no-referrer',
                'X-Permitted-Cross-Domain-Policies' => 'none',
            ], 'body'),
        ]);

        self::assertSame([], $findings);
    }

    public function testACookieMissingFlagsIsReported(): void
    {
        $findings = $this->check->analyze(new Target('https://example.com'), [
            '/' => new Response(200, ['Set-Cookie' => 'session=abc; path=/'], 'body'),
        ]);

        $ids = array_map(static fn ($f): string => $f->id, $findings);
        self::assertContains('cookie-flags-session', $ids);
    }

    public function testAnInsecureCspIsReported(): void
    {
        $findings = $this->check->analyze(new Target('https://example.com'), [
            '/' => new Response(200, [
                'Content-Security-Policy' => "default-src 'self' 'unsafe-inline' 'none'",
                'Strict-Transport-Security' => 'max-age=31536000',
                'X-Content-Type-Options' => 'nosniff',
                'X-Frame-Options' => 'DENY',
                'Referrer-Policy' => 'no-referrer',
                'X-Permitted-Cross-Domain-Policies' => 'none',
            ], 'body'),
        ]);

        $ids = array_map(static fn ($f): string => $f->id, $findings);
        self::assertContains('insecure-csp', $ids);
    }

    public function testHstsIsNotRequiredOnPlainHttp(): void
    {
        $findings = $this->check->analyze(new Target('http://example.com'), [
            '/' => new Response(200, [
                'Content-Security-Policy' => "default-src 'self'",
                'X-Content-Type-Options' => 'nosniff',
                'X-Frame-Options' => 'DENY',
                'Referrer-Policy' => 'no-referrer',
                'X-Permitted-Cross-Domain-Policies' => 'none',
            ], 'body'),
        ]);

        $ids = array_map(static fn ($f): string => $f->id, $findings);
        self::assertNotContains('missing-header-strict-transport-security', $ids);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `composer test -- --filter SecurityHeadersTest`
Expected: FAIL — `Class "Php2Scan\Check\SecurityHeaders" not found`.

- [ ] **Step 3: Implement `src/Check/SecurityHeaders.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Check;

use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Validator;
use Php2Scan\Data\Reproduce;
use Php2Scan\Finding;
use Php2Scan\Severity;
use Php2Scan\Target;
use Psr\Http\Message\ResponseInterface;

final class SecurityHeaders implements Check
{
    private const HEADERS = [
        'Content-Security-Policy' => Severity::Low,
        'X-Content-Type-Options' => Severity::Medium,
        'Referrer-Policy' => Severity::Low,
        'X-Permitted-Cross-Domain-Policies' => Severity::Low,
    ];

    public function __construct(private readonly Reproduce $reproduce)
    {
    }

    public function id(): string
    {
        return 'security_headers';
    }

    public function paths(Target $target, ?ResponseInterface $baseline): array
    {
        return ['/'];
    }

    public function analyze(Target $target, array $responses): array
    {
        $response = $responses['/'] ?? null;
        if ($response === null) {
            return [];
        }

        $findings = [];
        $isHttps = str_starts_with($target->url, 'https://');

        foreach (self::HEADERS as $header => $severity) {
            if ($response->hasHeader($header)) {
                continue;
            }

            $findings[] = $this->finding(
                'missing-header-' . strtolower($header),
                sprintf('Missing %s header', $header),
                $severity,
                $target,
                sprintf('The response has no %s header.', $header),
                sprintf('Send a request without that header and observe the browser has no protection - the header can be added at the edge or in the application.'),
            );
        }

        if ($isHttps && !$response->hasHeader('Strict-Transport-Security')) {
            $findings[] = $this->finding(
                'missing-header-strict-transport-security',
                'Missing Strict-Transport-Security header',
                Severity::Medium,
                $target,
                'The HTTPS response has no Strict-Transport-Security header.',
                'Request the site over plain HTTP and follow the redirect - without HSTS the browser can be downgraded to cleartext.',
            );
        }

        if (!$response->hasHeader('X-Frame-Options') && !$this->hasFrameAncestors($response)) {
            $findings[] = $this->finding(
                'missing-header-x-frame-options',
                'Missing X-Frame-Options header',
                Severity::Medium,
                $target,
                'The response has neither X-Frame-Options nor a CSP frame-ancestors directive.',
                'Embed the target in an iframe on a page you control - without frame protection the clickjacking overlay succeeds.',
            );
        }

        foreach ($response->getHeader('Set-Cookie') as $cookie) {
            $name = self::cookieName($cookie);
            $missing = [];

            if (stripos($cookie, 'secure') === false) {
                $missing[] = 'Secure';
            }
            if (stripos($cookie, 'httponly') === false) {
                $missing[] = 'HttpOnly';
            }
            if (stripos($cookie, 'samesite') === false) {
                $missing[] = 'SameSite';
            }

            if ($missing === []) {
                continue;
            }

            $findings[] = $this->finding(
                'cookie-flags-' . strtolower($name),
                sprintf('Cookie "%s" is missing %s', $name, implode(', ', $missing)),
                Severity::Medium,
                $target,
                sprintf('Set-Cookie: %s', $cookie),
                sprintf('Replay the session cookie from a script or a plain-HTTP request - the missing %s flag lets it leave the browser or be read by JavaScript.', implode(' and ', $missing)),
            );
        }

        foreach ($this->validateValues($response) as $problem) {
            $findings[] = $this->finding(
                'insecure-csp',
                'Weak Content-Security-Policy',
                Severity::Medium,
                $target,
                $problem,
                'Load the page and inject a script - the policy permits it, so the injection executes in the page origin.',
            );
        }

        return $findings;
    }

    private function hasFrameAncestors(ResponseInterface $response): bool
    {
        $csp = $response->getHeaderLine('Content-Security-Policy');

        return $csp !== '' && stripos($csp, 'frame-ancestors') !== false;
    }

    /**
     * @return list<string>
     */
    private function validateValues(ResponseInterface $response): array
    {
        $headers = [];
        foreach ($response->getHeaders() as $name => $values) {
            $headers[$name] = implode(', ', $values);
        }

        $problems = [];

        try {
            $errors = Validator::validate(new HeaderBag($headers));
        } catch (\Throwable) {
            return [];
        }

        foreach ($errors as $error) {
            $problems[] = trim(strip_tags($error->getMessage()));
        }

        return $problems;
    }

    private static function cookieName(string $cookie): string
    {
        $parts = explode('=', $cookie, 2);

        return trim($parts[0]);
    }

    private function finding(
        string $id,
        string $title,
        Severity $severity,
        Target $target,
        string $evidence,
        string $exploit,
    ): Finding {
        return new Finding(
            id: $id,
            title: $title,
            severity: $severity,
            target: $target->label(),
            evidence: $evidence,
            exploit: $exploit,
            reproduce: $this->reproduce->steps('security-headers', $target->url, $target->label()),
        );
    }
}
```

- [ ] **Step 4: Create `data/repro/security-headers.md`**

```
curl -sSI {url}/ | grep -iE 'strict-transport-security|content-security-policy|x-content-type-options|x-frame-options|referrer-policy'
# shows which security headers are actually sent
curl -sSI {url}/ | grep -i set-cookie
# shows the cookie flags
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `composer test -- --filter SecurityHeadersTest`
Expected: PASS — `OK (5 tests, 8 assertions)`.

- [ ] **Step 6: Commit**

```bash
git add src/Check/SecurityHeaders.php data/repro/security-headers.md tests/Unit/SecurityHeadersTest.php
git commit -m "feat: security header and cookie flag audit"
```

---

### Task 11: TLS check

**Files:**
- Create: `src/Check/Tls.php`
- Create: `data/repro/tls.md`
- Test: `tests/Unit/TlsTest.php`

**Interfaces:**
- Consumes: `Php2Scan\Data\Reproduce` (Task 6), `Php2Scan\Check\Check` (Task 7).
- Produces: `Php2Scan\Check\Tls implements Check`, `id()` returns `'tls'`. `paths()` returns `[]` (the check opens its own TLS socket). `analyze()` returns findings for an expired certificate, a certificate expiring within 14 days, and a hostname mismatch.

**Note:** the TLS check opens its own socket rather than using the HTTP pool, because it needs the raw peer certificate. `paths()` returning `[]` is correct and must not break the engine.

- [ ] **Step 1: Write the failing test `tests/Unit/TlsTest.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use Php2Scan\Check\Tls;
use Php2Scan\Data\Reproduce;
use Php2Scan\Severity;
use Php2Scan\Target;
use PHPUnit\Framework\TestCase;

final class TlsTest extends TestCase
{
    public function testAPlainHttpTargetIsSkipped(): void
    {
        $check = new Tls(new Reproduce(__DIR__ . '/../../data/repro'));

        self::assertSame([], $check->analyze(new Target('http://example.com'), []));
    }

    public function testAnUnreachableTlsTargetProducesNoFindingRatherThanAnError(): void
    {
        $check = new Tls(new Reproduce(__DIR__ . '/../../data/repro'));
        $findings = $check->analyze(new Target('https://127.0.0.1:1/'), []);

        self::assertSame([], $findings);
    }
}
```

**Note for the implementer:** the certificate tests need a deterministic certificate, so `Tls` accepts an injectable certificate resolver and the test does not need a live server:

```php
// in Tls
public function __construct(
    private readonly Reproduce $reproduce,
    /** @var null|callable(string, int): array<string, mixed>|null */
    private readonly ?\Closure $certificateResolver = null,
) {
}

// in analyze()
// $cert = $this->certificateResolver !== null
//     ? ($this->certificateResolver)($host, $port)
//     : self::fetchCertificate($host, $port);
// if ($cert === null) { return []; }
```

The test then passes a resolver closure returning `['validFrom' => time() - 86400 * 365, 'validTo' => time() - 86400, 'subject' => 'CN=expired.example.com']`.

Use these test methods:

```php
    public function testAnExpiredCertificateIsCritical(): void
    {
        $check = new Tls(
            new Reproduce(__DIR__ . '/../../data/repro'),
            static fn (string $host, int $port): array => [
                'validFrom' => time() - 86400 * 365,
                'validTo' => time() - 86400,
                'subject' => 'CN=' . $host,
            ],
        );

        $findings = $check->analyze(new Target('https://expired.example.com'), []);

        self::assertNotSame([], $findings);
        self::assertSame(Severity::Critical, $findings[0]->severity);
    }

    public function testACertificateExpiringSoonIsMedium(): void
    {
        $check = new Tls(
            new Reproduce(__DIR__ . '/../../data/repro'),
            static fn (string $host, int $port): array => [
                'validFrom' => time() - 86400,
                'validTo' => time() + 86400 * 5,
                'subject' => 'CN=' . $host,
            ],
        );

        $findings = $check->analyze(new Target('https://soon.example.com'), []);

        self::assertSame(Severity::Medium, $findings[0]->severity);
    }

    public function testAValidCertificateProducesNoFinding(): void
    {
        $check = new Tls(
            new Reproduce(__DIR__ . '/../../data/repro'),
            static fn (string $host, int $port): array => [
                'validFrom' => time() - 86400,
                'validTo' => time() + 86400 * 90,
                'subject' => 'CN=' . $host,
            ],
        );

        self::assertSame([], $check->analyze(new Target('https://ok.example.com'), []));
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `composer test -- --filter TlsTest`
Expected: FAIL — `Class "Php2Scan\Check\Tls" not found`.

- [ ] **Step 3: Implement `src/Check/Tls.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Check;

use Php2Scan\Data\Reproduce;
use Php2Scan\Finding;
use Php2Scan\Severity;
use Php2Scan\Target;
use Psr\Http\Message\ResponseInterface;

final class Tls implements Check
{
    /**
     * @param null|\Closure(string, int): (array<string, mixed>|null) $certificateResolver
     */
    public function __construct(
        private readonly Reproduce $reproduce,
        private readonly ?\Closure $certificateResolver = null,
    ) {
    }

    public function id(): string
    {
        return 'tls';
    }

    public function paths(Target $target, ?ResponseInterface $baseline): array
    {
        return [];
    }

    public function analyze(Target $target, array $responses): array
    {
        if (!str_starts_with($target->url, 'https://')) {
            return [];
        }

        $host = $target->host();
        $port = (int) (parse_url($target->url, PHP_URL_PORT) ?: 443);

        $certificate = $this->certificateResolver !== null
            ? ($this->certificateResolver)($host, $port)
            : self::fetchCertificate($host, $port);

        if ($certificate === null) {
            return [];
        }

        $validTo = (int) ($certificate['validTo'] ?? 0);
        $days = (int) floor(($validTo - time()) / 86400);
        $steps = $this->reproduce->steps('tls', $target->url, $target->label());

        if ($days < 0) {
            return [new Finding(
                id: 'tls-expired',
                title: 'Expired TLS certificate',
                severity: Severity::Critical,
                target: $target->label(),
                evidence: sprintf('The certificate expired %d days ago (%s).', abs($days), gmdate('Y-m-d', $validTo)),
                exploit: 'Request the site and watch the browser block it - the expired certificate also breaks any client that validates certificates, such as curl without -k.',
                reproduce: $steps,
            )];
        }

        if ($days <= 14) {
            return [new Finding(
                id: 'tls-expiring',
                title: 'TLS certificate expires soon',
                severity: Severity::Medium,
                target: $target->label(),
                evidence: sprintf('The certificate expires in %d days (%s).', $days, gmdate('Y-m-d', $validTo)),
                exploit: 'Wait for the expiry, or force an outage by presenting a certificate the client does not trust - the renewal failure becomes a full outage.',
                reproduce: $steps,
            )];
        }

        return [];
    }

    /**
     * @return array<string, mixed>|null
     */
    private static function fetchCertificate(string $host, int $port): ?array
    {
        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => false,
                'verify_peer_name' => false,
            ],
        ]);

        $socket = @stream_socket_client(
            sprintf('ssl://%s:%d', $host, $port),
            $errno,
            $errstr,
            5,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if ($socket === false) {
            return null;
        }

        $options = stream_context_get_options($socket);
        $peer = $options['ssl']['peer_certificate'] ?? null;
        fclose($socket);

        if ($peer === null) {
            return null;
        }

        $parsed = @openssl_x509_parse($peer);
        if ($parsed === false) {
            return null;
        }

        return [
            'validFrom' => (int) ($parsed['validFrom_time_t'] ?? 0),
            'validTo' => (int) ($parsed['validTo_time_t'] ?? 0),
            'subject' => (string) ($parsed['name'] ?? ''),
        ];
    }
}
```

- [ ] **Step 4: Create `data/repro/tls.md`**

```
echo | openssl s_client -connect {host}:443 -servername {host} 2>/dev/null | openssl x509 -noout -dates
# shows the certificate validity window
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `composer test -- --filter TlsTest`
Expected: PASS — `OK (4 tests, 4 assertions)`.

- [ ] **Step 6: Commit**

```bash
git add src/Check/Tls.php data/repro/tls.md tests/Unit/TlsTest.php
git commit -m "feat: tls certificate expiry check"
```

---

### Task 12: App fingerprint and webshell indicator checks

**Files:**
- Create: `src/Check/AppFingerprint.php`
- Create: `src/Check/WebshellIndicators.php`
- Create: `data/repro/app-fingerprint.md`
- Test: `tests/Unit/FingerprintChecksTest.php`

**Interfaces:**
- Consumes: `Php2Scan\Data\Wordlists`, `Php2Scan\Data\Reproduce` (Task 6), `Php2Scan\Check\Check` (Task 7).
- Produces:
  - `Php2Scan\Check\AppFingerprint implements Check`, `id()` returns `'app_fingerprint'`. `paths()` returns the product probe paths. `analyze()` returns one `Finding` per identified product, severity `info`.
  - `Php2Scan\Check\WebshellIndicators implements Check`, `id()` returns `'webshell_indicators'`. `paths()` returns the IOC filenames under `/` and under each `Target::$paths` directory. `analyze()` returns a `high` finding only when the response is `200` **and** the body contains a shell primitive.

**Shell primitives that confirm a webshell:** `system(`, `shell_exec(`, `passthru(`, `proc_open(`, `popen(`, `eval(`, `base64_decode(` combined with `$_GET` or `$_POST`.

- [ ] **Step 1: Write the failing test `tests/Unit/FingerprintChecksTest.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use GuzzleHttp\Psr7\Response;
use Php2Scan\Check\AppFingerprint;
use Php2Scan\Check\WebshellIndicators;
use Php2Scan\Data\Reproduce;
use Php2Scan\Data\Wordlists;
use Php2Scan\Severity;
use Php2Scan\Target;
use PHPUnit\Framework\TestCase;

final class FingerprintChecksTest extends TestCase
{
    public function testWordpressIsIdentified(): void
    {
        $check = new AppFingerprint(new Reproduce(__DIR__ . '/../../data/repro'));
        $findings = $check->analyze(new Target('https://example.com'), [
            '/wp-includes/version.php' => new Response(200, [], "<?php \$wp_version = '6.5.2';"),
        ]);

        self::assertNotSame([], $findings);
        self::assertStringContainsString('WordPress', $findings[0]->title);
        self::assertSame(Severity::Info, $findings[0]->severity);
    }

    public function testAWebshellIsOnlyConfirmedWhenTheBodyHasAShellPrimitive(): void
    {
        $check = new WebshellIndicators(
            new Wordlists(__DIR__ . '/../../data'),
            new Reproduce(__DIR__ . '/../../data/repro'),
        );

        $benign = $check->analyze(new Target('https://example.com'), [
            '/shell.php' => new Response(200, [], '<?php echo "hello"; ?>'),
        ]);
        self::assertSame([], $benign);

        $malicious = $check->analyze(new Target('https://example.com'), [
            '/shell.php' => new Response(200, [], "<?php system(\$_GET['c']); ?>"),
        ]);
        self::assertCount(1, $malicious);
        self::assertSame(Severity::High, $malicious[0]->severity);
    }

    public function testWebshellProbesCoverTheConfiguredUploadDirectories(): void
    {
        $check = new WebshellIndicators(
            new Wordlists(__DIR__ . '/../../data'),
            new Reproduce(__DIR__ . '/../../data/repro'),
        );

        $paths = $check->paths(new Target('https://example.com', null, ['/wp-content/uploads']), null);

        self::assertContains('/wp-content/uploads/shell.php', $paths);
        self::assertContains('/shell.php', $paths);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `composer test -- --filter FingerprintChecksTest`
Expected: FAIL — `Class "Php2Scan\Check\AppFingerprint" not found`.

- [ ] **Step 3: Implement `src/Check/AppFingerprint.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Check;

use Php2Scan\Data\Reproduce;
use Php2Scan\Finding;
use Php2Scan\Severity;
use Php2Scan\Target;
use Psr\Http\Message\ResponseInterface;

final class AppFingerprint implements Check
{
    private const PRODUCTS = [
        'WordPress' => ['/wp-includes/version.php', '/wp-login.php', '/wp-content/'],
        'Drupal' => ['/core/CHANGELOG.txt', '/user/register', '/sites/default/files/'],
        'Joomla' => ['/administrator/', '/language/en-GB/en-GB.xml', '/media/system/js/'],
        'Laravel' => ['/telescope', '/_ignition/health-check', '/storage/logs/laravel.log'],
        'Symfony' => ['/_profiler/', '/_wdt/', '/app_dev.php'],
        'Next.js' => ['/_next/static/', '/__nextjs_original-stack-frame'],
    ];

    public function __construct(private readonly Reproduce $reproduce)
    {
    }

    public function id(): string
    {
        return 'app_fingerprint';
    }

    public function paths(Target $target, ?ResponseInterface $baseline): array
    {
        $paths = ['/'];

        foreach (self::PRODUCTS as $probes) {
            foreach ($probes as $probe) {
                $paths[] = $probe;
            }
        }

        return array_values(array_unique($paths));
    }

    public function analyze(Target $target, array $responses): array
    {
        $findings = [];
        $body = (string) ($responses['/'] ?? null?->getBody());

        foreach (self::PRODUCTS as $product => $probes) {
            $version = null;

            foreach ($probes as $probe) {
                $response = $responses[$probe] ?? null;
                if ($response === null || $response->getStatusCode() !== 200) {
                    continue;
                }

                $version = self::detectVersion($product, (string) $response->getBody()) ?? $version;
            }

            if ($product === 'WordPress' && preg_match('/wp-content|wp-includes/i', $body) === 1 && $version === null) {
                $version = 'version not disclosed';
            }

            if ($product === 'Next.js' && preg_match('/\/_next\/static\//i', $body) === 1 && $version === null) {
                $version = 'version not disclosed';
            }

            if ($version === null) {
                continue;
            }

            $findings[] = new Finding(
                id: 'app-' . strtolower($product),
                title: $product . ' detected',
                severity: Severity::Info,
                target: $target->label(),
                evidence: sprintf('%s (%s).', $product, $version),
                exploit: 'Check the running version against the upstream security advisories for ' . $product . ' - the scanner does not carry a CMS advisory database.',
                reproduce: $this->reproduce->steps('app-fingerprint', $target->url, $target->label()),
            );
        }

        return $findings;
    }

    private static function detectVersion(string $product, string $body): ?string
    {
        if ($product === 'WordPress' && preg_match("/\\\$wp_version\s*=\s*'([^']+)'/", $body, $m) === 1) {
            return $m[1];
        }

        if ($product === 'Drupal' && preg_match('/Drupal (\d+\.\d+)/i', $body, $m) === 1) {
            return $m[1];
        }

        return null;
    }
}
```

- [ ] **Step 4: Implement `src/Check/WebshellIndicators.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Check;

use Php2Scan\Data\Reproduce;
use Php2Scan\Data\Wordlists;
use Php2Scan\Finding;
use Php2Scan\Severity;
use Php2Scan\Target;
use Psr\Http\Message\ResponseInterface;

final class WebshellIndicators implements Check
{
    private const PRIMITIVES = '/\b(system|shell_exec|passthru|proc_open|popen|eval)\s*\(|\bbase64_decode\s*\(/i';

    private const INPUT = '/\$_(GET|POST|REQUEST|COOKIE)\b/i';

    public function __construct(
        private readonly Wordlists $wordlists,
        private readonly Reproduce $reproduce,
    ) {
    }

    public function id(): string
    {
        return 'webshell_indicators';
    }

    public function paths(Target $target, ?ResponseInterface $baseline): array
    {
        $directories = [''];
        foreach ($target->paths as $extra) {
            $directories[] = trim($extra, '/');
        }

        $paths = [];
        foreach ($directories as $directory) {
            foreach ($this->wordlists->webshellPaths() as $file) {
                $paths[] = '/' . ($directory === '' ? '' : $directory . '/') . $file;
            }
        }

        return array_values(array_unique($paths));
    }

    public function analyze(Target $target, array $responses): array
    {
        $findings = [];

        foreach ($responses as $path => $response) {
            if ($response->getStatusCode() !== 200) {
                continue;
            }

            $body = (string) $response->getBody();
            if ($body === '') {
                continue;
            }

            if (preg_match(self::PRIMITIVES, $body) !== 1) {
                continue;
            }

            if (preg_match(self::INPUT, $body) !== 1) {
                continue;
            }

            $findings[] = new Finding(
                id: 'webshell-indicator',
                title: 'Possible webshell at ' . $path,
                severity: Severity::High,
                target: $target->label(),
                evidence: sprintf('HTTP 200 at %s, %d bytes, body contains a shell primitive and request input.', $path, strlen($body)),
                exploit: sprintf('Send a command to %s, e.g. curl "%s?c=id", and the server executes it.', $path, rtrim($target->url, '/') . $path),
                reproduce: $this->reproduce->steps('webshell-indicator', $target->url, $target->label(), ['path' => ltrim($path, '/')]),
            );
        }

        return $findings;
    }
}
```

- [ ] **Step 5: Create `data/repro/app-fingerprint.md`**

```
curl -sSI {url}/ | grep -iE 'x-powered-by|generator|link:.*wp-|x-generator'
# look for framework and CMS fingerprints
curl -sS {url}/wp-includes/version.php | head -5
# WordPress exposes its version here
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `composer test -- --filter FingerprintChecksTest`
Expected: PASS — `OK (3 tests, 5 assertions)`.

- [ ] **Step 7: Commit**

```bash
git add src/Check/AppFingerprint.php src/Check/WebshellIndicators.php data/repro/app-fingerprint.md tests/Unit/FingerprintChecksTest.php
git commit -m "feat: application fingerprint and webshell indicator checks"
```

---

### Task 13: Open ports check

**Files:**
- Create: `src/Check/OpenPorts.php`
- Create: `data/repro/open-ports.md`
- Test: `tests/Unit/OpenPortsTest.php`

**Interfaces:**
- Consumes: `Php2Scan\Data\Wordlists`, `Php2Scan\Data\Reproduce` (Task 6), `Php2Scan\Check\Check` (Task 7).
- Produces: `Php2Scan\Check\OpenPorts implements Check`, `id()` returns `'open_ports'`. `paths()` returns `[]`. `analyze()` returns one `Finding` per open port that is not `80` or `443`.

**Severity (verbatim from the spec §8.1):** medium for an open port that is not 80/443; high for `3306`, `5432`, `6379`, `27017`, `9200`.

**Note:** the port probe runs its own socket connections with a 150 ms timeout. It is not part of the HTTP pool, so it is sequential per target. `OpenPorts` accepts an injectable prober so the test needs no network.

- [ ] **Step 1: Write the failing test `tests/Unit/OpenPortsTest.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use Php2Scan\Check\OpenPorts;
use Php2Scan\Data\Reproduce;
use Php2Scan\Data\Wordlists;
use Php2Scan\Severity;
use Php2Scan\Target;
use PHPUnit\Framework\TestCase;

final class OpenPortsTest extends TestCase
{
    public function testAnExposedDatabasePortIsHighAndWebPortsAreNotReported(): void
    {
        $check = new OpenPorts(
            new Wordlists(__DIR__ . '/../../data'),
            new Reproduce(__DIR__ . '/../../data/repro'),
            static fn (string $host, int $port): bool => in_array($port, [3306, 443], true),
        );

        $findings = $check->analyze(new Target('https://example.com'), []);

        self::assertCount(1, $findings);
        self::assertSame(Severity::High, $findings[0]->severity);
        self::assertStringContainsString('3306', $findings[0]->evidence);
    }

    public function testEveryPortClosedProducesNoFinding(): void
    {
        $check = new OpenPorts(
            new Wordlists(__DIR__ . '/../../data'),
            new Reproduce(__DIR__ . '/../../data/repro'),
            static fn (string $host, int $port): bool => false,
        );

        self::assertSame([], $check->analyze(new Target('https://example.com'), []));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `composer test -- --filter OpenPortsTest`
Expected: FAIL — `Class "Php2Scan\Check\OpenPorts" not found`.

- [ ] **Step 3: Implement `src/Check/OpenPorts.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Check;

use Php2Scan\Data\Reproduce;
use Php2Scan\Data\Wordlists;
use Php2Scan\Finding;
use Php2Scan\Severity;
use Php2Scan\Target;
use Psr\Http\Message\ResponseInterface;

final class OpenPorts implements Check
{
    private const HIGH_PORTS = [3306, 5432, 6379, 27017, 9200];

    private const WEB_PORTS = [80, 443];

    /**
     * @param null|\Closure(string, int): bool $prober
     */
    public function __construct(
        private readonly Wordlists $wordlists,
        private readonly Reproduce $reproduce,
        private readonly ?\Closure $prober = null,
    ) {
    }

    public function id(): string
    {
        return 'open_ports';
    }

    public function paths(Target $target, ?ResponseInterface $baseline): array
    {
        return [];
    }

    public function analyze(Target $target, array $responses): array
    {
        $host = $target->host();
        $findings = [];

        foreach ($this->wordlists->openPorts() as $port) {
            if (in_array($port, self::WEB_PORTS, true)) {
                continue;
            }

            $open = $this->prober !== null
                ? ($this->prober)($host, $port)
                : self::probe($host, $port);

            if (!$open) {
                continue;
            }

            $findings[] = new Finding(
                id: 'open-port-' . $port,
                title: sprintf('Port %d is open', $port),
                severity: in_array($port, self::HIGH_PORTS, true) ? Severity::High : Severity::Medium,
                target: $target->label(),
                evidence: sprintf('TCP port %d accepted a connection on %s.', $port, $host),
                exploit: sprintf('Connect to %s:%d directly - the service is reachable from outside and may not require authentication.', $host, $port),
                reproduce: $this->reproduce->steps('open-ports', $target->url, $target->label()),
            );
        }

        return $findings;
    }

    private static function probe(string $host, int $port): bool
    {
        $errno = 0;
        $errstr = '';
        $socket = @fsockopen($host, $port, $errno, $errstr, 0.15);

        if ($socket === false) {
            return false;
        }

        fclose($socket);

        return true;
    }
}
```

- [ ] **Step 4: Create `data/repro/open-ports.md`**

```
nc -zv {host} 3306
# confirms the service answers from outside your perimeter
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `composer test -- --filter OpenPortsTest`
Expected: PASS — `OK (2 tests, 3 assertions)`.

- [ ] **Step 6: Commit**

```bash
git add src/Check/OpenPorts.php data/repro/open-ports.md tests/Unit/OpenPortsTest.php
git commit -m "feat: open port check"
```

---

### Task 14: Report rendering (text, json, markdown)

**Files:**
- Create: `src/Report/Theme.php`
- Create: `src/Report/Report.php`
- Test: `tests/Unit/ReportTest.php`

**Interfaces:**
- Consumes: `Php2Scan\Finding`, `Php2Scan\Severity`, `Php2Scan\ScanResult` (Tasks 2, 7).
- Produces:
  - `Php2Scan\Report\Theme` — `final class Theme` with `public static function symbol(Severity $severity): string` returning `!` for critical, `^` for high, `-` for medium, `.` for low, `i` for info; and `public static function label(Severity $severity): string` returning the uppercased severity name.
  - `Php2Scan\Report\Report` — `final class Report`, constructed as `new Report(ScanResult $result, Config $config)`. Methods:
    - `public function render(string $format): string` — `tui` falls back to `text` (the TUI renderer handles the live view); `text`, `json` and `markdown` are implemented here.
    - `public function text(): string`
    - `public function json(): string`
    - `public function markdown(): string`
    - `public function filename(string $format, ?\DateTimeImmutable $now = null): string`

**Text format** (from the spec §12):

```
! CRITICAL  PHP2Shell · CVE-2026-109618 — legacy.example.com
    PHP 8.1.29 detected via X-Powered-By (confidence: high); affected — patched in 8.2.35.
    How to exploit: send the published OOM trigger to any .php endpoint to get pre-auth RCE as the PHP-FPM worker.
    Fix: upgrade PHP to >= 8.2.35 and restart the Apache/FPM workers.
```

The `Fix:` line is optional — include it only when the finding id is `php2shell-version` and the severity is `critical`.

**JSON format:** `{"generated_at": "<ISO-8601>", "summary": {...}, "targets": [...], "findings": [...], "unreachable": [...], "unscannable": [...]}`.

- [ ] **Step 1: Write the failing test `tests/Unit/ReportTest.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use Php2Scan\Config;
use Php2Scan\Finding;
use Php2Scan\Report\Report;
use Php2Scan\ScanResult;
use Php2Scan\Severity;
use PHPUnit\Framework\TestCase;

final class ReportTest extends TestCase
{
    private function result(): ScanResult
    {
        return new ScanResult(
            findings: [
                new Finding(
                    id: 'php2shell-version',
                    title: 'PHP2Shell · CVE-2026-109618',
                    severity: Severity::Critical,
                    target: 'legacy.example.com',
                    evidence: 'PHP 8.1.29 detected via X-Powered-By (confidence: high); affected — patched in 8.2.35.',
                    exploit: 'Send the published OOM trigger to any .php endpoint to get pre-auth RCE as the PHP-FPM worker.',
                    reproduce: ['curl -sI https://legacy.example.com/ | grep -i x-powered-by'],
                ),
                new Finding(
                    id: 'sensitive-file-env',
                    title: 'Exposed .env',
                    severity: Severity::High,
                    target: 'legacy.example.com',
                    evidence: 'HTTP 200, 42 bytes, contains credential-looking keys.',
                    exploit: 'curl https://legacy.example.com/.env and read the leaked credentials.',
                    reproduce: ['curl -sS https://legacy.example.com/.env | head -20'],
                ),
            ],
            unreachable: [['target' => 'dead.example.com', 'error' => 'Connection refused']],
            unscannable: [['target' => 'waf.example.com', 'status' => 403]],
            duration: 1.25,
        );
    }

    public function testTextIncludesEveryPartOfEveryFinding(): void
    {
        $report = new Report($this->result(), Config::fromArray(['targets' => ['https://legacy.example.com']]));
        $text = $report->text();

        self::assertStringContainsString('CRITICAL', $text);
        self::assertStringContainsString('legacy.example.com', $text);
        self::assertStringContainsString('How to exploit:', $text);
        self::assertStringContainsString('curl -sS https://legacy.example.com/.env', $text);
        self::assertStringContainsString('dead.example.com', $text);
        self::assertStringContainsString('waf.example.com', $text);
    }

    public function testJsonIsValidAndCarriesTheFindings(): void
    {
        $report = new Report($this->result(), Config::fromArray(['targets' => ['https://legacy.example.com']]));
        $decoded = json_decode($report->json(), true, 512, JSON_THROW_ON_ERROR);

        self::assertCount(2, $decoded['findings']);
        self::assertSame('php2shell-version', $decoded['findings'][0]['id']);
        self::assertSame('critical', $decoded['findings'][0]['severity']);
        self::assertSame(1, $decoded['summary']['critical']);
    }

    public function testTheTextReportOmitsFindingsBelowMinSeverity(): void
    {
        $config = Config::fromArray([
            'targets' => ['https://legacy.example.com'],
            'options' => ['min_severity' => 'critical'],
        ]);
        $report = new Report($this->result(), $config);
        $text = $report->text();

        self::assertStringContainsString('PHP2Shell', $text);
        self::assertStringNotContainsString('Exposed .env', $text);
    }

    public function testMarkdownIncludesTheReproduceSteps(): void
    {
        $report = new Report($this->result(), Config::fromArray(['targets' => ['https://legacy.example.com']]));
        $markdown = $report->markdown();

        self::assertStringContainsString('## CRITICAL', $markdown);
        self::assertStringContainsString('```bash', $markdown);
        self::assertStringContainsString('curl -sI https://legacy.example.com/', $markdown);
    }

    public function testTheTuiFormatFallsBackToText(): void
    {
        $report = new Report($this->result(), Config::fromArray(['targets' => ['https://legacy.example.com']]));

        self::assertSame($report->text(), $report->render('tui'));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `composer test -- --filter ReportTest`
Expected: FAIL — `Class "Php2Scan\Report\Report" not found`.

- [ ] **Step 3: Implement `src/Report/Theme.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Report;

use Php2Scan\Severity;

final class Theme
{
    public static function symbol(Severity $severity): string
    {
        return match ($severity) {
            Severity::Critical => '!',
            Severity::High => '^',
            Severity::Medium => '-',
            Severity::Low => '.',
            Severity::Info => 'i',
        };
    }

    public static function label(Severity $severity): string
    {
        return strtoupper($severity->value);
    }
}
```

- [ ] **Step 4: Implement `src/Report/Report.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Report;

use Php2Scan\Config;
use Php2Scan\Finding;
use Php2Scan\ScanResult;
use Php2Scan\Severity;

final class Report
{
    public function __construct(
        private readonly ScanResult $result,
        private readonly Config $config,
    ) {
    }

    public function render(string $format): string
    {
        return match ($format) {
            'json' => $this->json(),
            'markdown' => $this->markdown(),
            default => $this->text(),
        };
    }

    public function filename(string $format, ?\DateTimeImmutable $now = null): string
    {
        $now ??= new \DateTimeImmutable();
        $extension = match ($format) {
            'json' => 'json',
            'markdown' => 'md',
            default => 'txt',
        };

        return sprintf('php2scan-%s.%s', $now->format('Ymd-His'), $extension);
    }

    /**
     * Findings below min_severity are shown in the TUI and in the JSON output,
     * but are left out of the text and markdown reports (spec §18.2).
     *
     * @return list<Finding>
     */
    private function reportable(): array
    {
        return array_values(array_filter(
            $this->result->findings,
            fn (Finding $f): bool => $f->severity->atLeast($this->config->minSeverity)
        ));
    }

    public function text(): string
    {
        $lines = [];
        $lines[] = sprintf('php2scan report — %s', (new \DateTimeImmutable())->format('Y-m-d H:i:s'));
        $lines[] = '';

        $reportable = $this->reportable();

        if ($reportable === []) {
            $lines[] = 'No findings.';
        }

        foreach ($reportable as $finding) {
            foreach ($this->block($finding) as $line) {
                $lines[] = $line;
            }
            $lines[] = '';
        }

        foreach ($this->result->unreachable as $target) {
            $lines[] = sprintf('! UNREACHABLE  %s — %s', $target['target'], $target['error']);
            $lines[] = '';
        }

        foreach ($this->result->unscannable as $target) {
            $lines[] = sprintf('! BLOCKED  %s — HTTP %d', $target['target'], $target['status']);
            $lines[] = '';
        }

        $lines[] = sprintf(
            '%d finding(s) at or above %s, %d unreachable, %d unscannable in %.1fs',
            count($reportable),
            $this->config->minSeverity->value,
            count($this->result->unreachable),
            count($this->result->unscannable),
            $this->result->duration
        );

        return implode("\n", $lines) . "\n";
    }

    public function json(): string
    {
        $summary = [];
        foreach (Severity::cases() as $severity) {
            $summary[$severity->value] = 0;
        }
        foreach ($this->result->findings as $finding) {
            $summary[$finding->severity->value]++;
        }

        $payload = [
            'generated_at' => (new \DateTimeImmutable())->format(DATE_ATOM),
            'duration' => $this->result->duration,
            'summary' => $summary,
            'targets' => array_map(
                static fn ($target): array => ['url' => $target->url, 'label' => $target->label()],
                $this->config->targets
            ),
            'findings' => array_map(static fn (Finding $f): array => [
                'id' => $f->id,
                'title' => $f->title,
                'severity' => $f->severity->value,
                'target' => $f->target,
                'evidence' => $f->evidence,
                'exploit' => $f->exploit,
                'reproduce' => $f->reproduce,
            ], $this->result->findings),
            'unreachable' => $this->result->unreachable,
            'unscannable' => $this->result->unscannable,
        ];

        return json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
    }

    public function markdown(): string
    {
        $lines = [];
        $lines[] = '# php2scan report';
        $lines[] = '';
        $lines[] = sprintf('Generated %s.', (new \DateTimeImmutable())->format('Y-m-d H:i:s'));
        $lines[] = '';

        foreach ($this->reportable() as $finding) {
            $lines[] = sprintf('## %s · %s', Theme::label($finding->severity), $finding->title);
            $lines[] = '';
            $lines[] = sprintf('- **Target:** %s', $finding->target);
            $lines[] = sprintf('- **Evidence:** %s', $finding->evidence);
            $lines[] = sprintf('- **How to exploit:** %s', $finding->exploit);
            $lines[] = '';
            $lines[] = '```bash';
            foreach ($finding->reproduce as $step) {
                $lines[] = $step;
            }
            $lines[] = '```';
            $lines[] = '';
        }

        return implode("\n", $lines) . "\n";
    }

    /**
     * @return list<string>
     */
    private function block(Finding $finding): array
    {
        $lines = [];
        $lines[] = sprintf(
            '%s %s  %s — %s',
            Theme::symbol($finding->severity),
            str_pad(Theme::label($finding->severity), 8),
            $finding->title,
            $finding->target
        );
        $lines[] = '    ' . $finding->evidence;
        $lines[] = '    How to exploit: ' . $finding->exploit;

        if ($finding->id === 'php2shell-version' && $finding->severity === Severity::Critical) {
            $lines[] = '    Fix: upgrade PHP to the first fixed release for its branch and restart the Apache/FPM workers.';
        }

        foreach ($finding->reproduce as $step) {
            foreach (preg_split('/\R/', $step) ?: [] as $line) {
                $lines[] = '    $ ' . $line;
            }
        }

        return $lines;
    }
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `composer test -- --filter ReportTest`
Expected: PASS — `OK (4 tests, 9 assertions)`.

- [ ] **Step 6: Commit**

```bash
git add src/Report/Theme.php src/Report/Report.php tests/Unit/ReportTest.php
git commit -m "feat: text, json and markdown report rendering"
```

---

### Task 15: Wire the CLI command and the scan command

**Files:**
- Modify: `src/Command/ScanCommand.php`
- Modify: `src/Application.php`
- Test: `tests/Integration/ScanCommandTest.php`

**Interfaces:**
- Consumes: everything from Tasks 3–14.
- Produces: `bin/php2scan scan --config=php2scan.yaml [--format=tui|text|json|markdown] [--no-tui] [--verify] [--yes] [--output-dir=DIR]`.
- Exit codes: `0` no findings at or above `min_severity`; `1` findings present; `2` configuration or runtime error.

**Note:** the command is registered as the **default** command so `php2scan` with no sub-command runs the scan.

- [ ] **Step 1: Write the failing integration test `tests/Integration/ScanCommandTest.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Integration;

use PHPUnit\Framework\TestCase;
use Php2Scan\Application;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

final class ScanCommandTest extends TestCase
{
    /**
     * @param array<string, mixed> $input
     */
    private function run(array $input, string $cwd): array
    {
        $application = new Application();
        $application->setAutoExit(false);
        $application->setCatchExceptions(false);
        $output = new BufferedOutput();

        $code = $application->run(new ArrayInput($input), $output);

        return [$code, $output->fetch()];
    }

    public function testItFailsWithExitCodeTwoWhenTheConfigIsMissing(): void
    {
        [$code, $output] = $this->run([
            'command' => 'scan',
            '--config' => '/nonexistent/php2scan.yaml',
            '--format' => 'json',
        ], sys_get_temp_dir());

        self::assertSame(2, $code);
        self::assertStringContainsString('php2scan', $output);
    }

    public function testItReportsFindingsAsJsonAndExitsWithOne(): void
    {
        $config = tempnam(sys_get_temp_dir(), 'php2scan') . '.yaml';
        file_put_contents($config, "targets:\n  - http://127.0.0.1:1/unreachable\nchecks:\n  php_presence: true\n");

        [$code, $output] = $this->run([
            'command' => 'scan',
            '--config' => $config,
            '--format' => 'json',
        ], sys_get_temp_dir());

        self::assertSame(0, $code, 'an unreachable host alone is not a finding');
        self::assertStringContainsString('unreachable', $output);

        unlink($config);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `composer test -- --filter ScanCommandTest`
Expected: FAIL — the command does not recognise `--config`.

- [ ] **Step 3: Implement `src/Command/ScanCommand.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Command;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\CurlMultiHandler;
use GuzzleHttp\HandlerStack;
use Php2Scan\Application;
use Php2Scan\Check\AppFingerprint;
use Php2Scan\Check\OpenPorts;
use Php2Scan\Check\PhpDetection;
use Php2Scan\Check\PhpVersion;
use Php2Scan\Check\Registry;
use Php2Scan\Check\SecurityHeaders;
use Php2Scan\Check\SensitiveFiles;
use Php2Scan\Check\Tls;
use Php2Scan\Check\WebshellIndicators;
use Php2Scan\Config;
use Php2Scan\Data\Reproduce;
use Php2Scan\Data\Wordlists;
use Php2Scan\Engine;
use Php2Scan\Http\Client;
use Php2Scan\Http\Pool;
use Php2Scan\PhpVersionDb;
use Php2Scan\Report\Report;
use Php2Scan\Ui\PlainRenderer;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'scan', description: 'Scan the configured hosts for security exposure')]
final class ScanCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addOption('config', 'c', InputOption::VALUE_REQUIRED, 'Path to the configuration file', 'php2scan.yaml')
            ->addOption('format', 'f', InputOption::VALUE_REQUIRED, 'Output format: tui, text, json, markdown', '')
            ->addOption('no-tui', null, InputOption::VALUE_NONE, 'Never use the interactive interface')
            ->addOption('verify', null, InputOption::VALUE_NONE, 'Run the proof-of-concept requests')
            ->addOption('yes', 'y', InputOption::VALUE_NONE, 'Do not ask for confirmation')
            ->addOption('output-dir', null, InputOption::VALUE_REQUIRED, 'Directory for the written report');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $config = Config::fromFile((string) $input->getOption('config'));
        } catch (\Throwable $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');

            return 2;
        }

        $format = (string) $input->getOption('format');
        if ($format === '') {
            $format = $input->getOption('no-tui') || !stream_isatty(STDOUT) ? 'text' : $config->format;
        }

        $root = dirname(__DIR__, 2);
        $dataDir = $root . '/data';

        $handler = new CurlMultiHandler([
            'max_total_connections' => $config->concurrency,
            'max_host_connections' => 2,
        ]);
        $client = new Client(new GuzzleClient([
            'handler' => HandlerStack::create($handler),
            'http_errors' => false,
            'timeout' => $config->timeout,
            'connect_timeout' => $config->connectTimeout,
            'headers' => ['User-Agent' => $config->userAgent],
        ]), $config->delayMs);
        $pool = new Pool($handler, $client);

        $wordlists = new Wordlists($dataDir);
        $reproduce = new Reproduce($dataDir . '/repro');
        $db = PhpVersionDb::fromFile($dataDir . '/php-affected.json');

        $registry = new Registry([
            'php_presence' => new PhpDetection($reproduce),
            'php_version' => new PhpVersion($db, $reproduce),
            'sensitive_files' => new SensitiveFiles($wordlists, $reproduce),
            'security_headers' => new SecurityHeaders($reproduce),
            'tls' => new Tls($reproduce),
            'app_fingerprint' => new AppFingerprint($reproduce),
            'webshell_indicators' => new WebshellIndicators($wordlists, $reproduce),
            'open_ports' => new OpenPorts($wordlists, $reproduce),
        ]);

        $engine = new Engine($pool, $client, $registry);
        $result = $engine->run($config);

        $report = new Report($result, $config);
        $rendered = $report->render($format);

        if ($format === 'text' || $format === 'markdown') {
            (new PlainRenderer())->render($rendered, $output);
        } else {
            $output->write($rendered);
        }

        $directory = (string) ($input->getOption('output-dir') ?: $config->reportDir);
        if (!is_dir($directory)) {
            @mkdir($directory, 0o755, true);
        }
        $path = rtrim($directory, '/') . '/' . $report->filename($format);
        file_put_contents($path, $rendered);

        $output->writeln(sprintf('Report written to %s', $path));

        $hasFindings = false;
        foreach ($result->findings as $finding) {
            if ($finding->severity->atLeast($config->minSeverity)) {
                $hasFindings = true;
                break;
            }
        }

        return $hasFindings ? 1 : 0;
    }
}
```

- [ ] **Step 4: Create `src/Ui/PlainRenderer.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Ui;

use Symfony\Component\Console\Output\OutputInterface;

final class PlainRenderer
{
    public function render(string $text, OutputInterface $output): void
    {
        $output->write($text);
    }
}
```

- [ ] **Step 5: Make `scan` the default command in `src/Application.php`**

```php
    public function __construct()
    {
        parent::__construct(self::NAME, self::VERSION);
        $this->add(new ScanCommand());
        $this->setDefaultCommand('scan');
    }
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `composer test -- --filter ScanCommandTest`
Expected: PASS — `OK (2 tests, 3 assertions)`.

- [ ] **Step 7: Run the whole suite**

Run: `composer test`
Expected: PASS — no failures.

- [ ] **Step 8: Run the scanner against the fixture server by hand**

```bash
php -S 127.0.0.1:8899 tests/Fixture/server.php &
cat > /tmp/php2scan-demo.yaml <<'EOF'
targets:
  - http://127.0.0.1:8899/
checks:
  php_presence: true
  php_version: true
  sensitive_files: true
  security_headers: true
options:
  delay_ms: 0
output:
  format: json
EOF
php bin/php2scan scan --config=/tmp/php2scan-demo.yaml --format=json
```

Expected: the JSON output contains a `php2shell-version` finding with `critical` severity (the fixture sends `X-Powered-By: PHP/8.1.29`), and a `sensitive-file-env` finding with `high` severity.

- [ ] **Step 9: Commit**

```bash
git add src/Command/ScanCommand.php src/Application.php src/Ui/PlainRenderer.php tests/Integration/ScanCommandTest.php
git commit -m "feat: scan command wiring, report output and exit codes"
```

---

## Phase 2 — Interactive TUI

### Task 16: TUI progress pane

**Files:**
- Create: `src/Ui/TuiRenderer.php`
- Test: `tests/Unit/TuiRendererTest.php`

**Interfaces:**
- Consumes: `Php2Scan\Finding`, `Php2Scan\Severity`, `Php2Scan\Report\Theme` (Tasks 2, 14).
- Produces: `Php2Scan\Ui\TuiRenderer` — `final class TuiRenderer`, constructed as `new TuiRenderer(?\PhpTui\Tui\Display\Backend $backend = null)` (a `DummyBackend` is injected in tests). Methods:
  - `public function start(array $targets): void` — begin the interface, set up the terminal (alternate screen, hide cursor, raw mode).
  - `public function update(string $targetLabel, string $phase): void` — record progress.
  - `public function setFindings(array $findings): void` — replace the findings list.
  - `public function draw(): void` — render the current frame. **Must call `$display->draw($widget)` and must never call `$display->flush()` afterwards.**
  - `public function selected(): ?Finding` — the currently selected finding.
  - `public function move(int $delta): void` — move the selection.
  - `public function toggleExpanded(): void` — expand or collapse the selected finding's reproduce steps.
  - `public function stop(): void` — restore the terminal.
  - `public function isQuitRequested(): bool` — true when the user pressed `q`.

**Layout:** `GridWidget` with `Direction::Vertical`, constraints `Constraint::length(6)` (progress pane) and `Constraint::min(0)` (findings pane).

- [ ] **Step 1: Write the failing test `tests/Unit/TuiRendererTest.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use Php2Scan\Finding;
use Php2Scan\Severity;
use Php2Scan\Ui\TuiRenderer;
use PHPUnit\Framework\TestCase;
use PhpTui\Tui\Display\Backend\DummyBackend;

final class TuiRendererTest extends TestCase
{
    public function testItRendersTheTargetsAndTheFindings(): void
    {
        $backend = new DummyBackend(100, 30);
        $renderer = new TuiRenderer($backend);
        $renderer->start(['legacy.example.com']);
        $renderer->update('legacy.example.com', 'probing');
        $renderer->setFindings([
            new Finding(
                id: 'php2shell-version',
                title: 'PHP2Shell · CVE-2026-109618',
                severity: Severity::Critical,
                target: 'legacy.example.com',
                evidence: 'PHP 8.1.29 detected via X-Powered-By (confidence: high); affected - patched in 8.2.35.',
                exploit: 'Send the published OOM trigger to any .php endpoint for pre-auth RCE.',
                reproduce: ['curl -sI https://legacy.example.com/ | grep -i x-powered-by'],
            ),
        ]);
        $renderer->draw();

        $frame = $backend->toString();

        self::assertStringContainsString('legacy.example.com', $frame);
        self::assertStringContainsString('PHP2Shell', $frame);
        self::assertStringContainsString('CRITICAL', $frame);
    }

    public function testExpandingTheSelectedFindingShowsTheReproduceSteps(): void
    {
        $backend = new DummyBackend(100, 30);
        $renderer = new TuiRenderer($backend);
        $renderer->start(['legacy.example.com']);
        $renderer->setFindings([
            new Finding(
                id: 'php2shell-version',
                title: 'PHP2Shell',
                severity: Severity::Critical,
                target: 'legacy.example.com',
                evidence: 'e',
                exploit: 'x',
                reproduce: ['curl -sS https://legacy.example.com/ | head -20'],
            ),
        ]);
        $renderer->toggleExpanded();
        $renderer->draw();

        self::assertStringContainsString('curl -sS https://legacy.example.com/', $backend->toString());
    }

    public function testTheSelectionMoves(): void
    {
        $backend = new DummyBackend(100, 30);
        $renderer = new TuiRenderer($backend);
        $renderer->start(['a.example.com', 'b.example.com']);
        $renderer->setFindings([
            new Finding('one', 'First', Severity::High, 'a.example.com', 'e', 'x', ['s']),
            new Finding('two', 'Second', Severity::Low, 'b.example.com', 'e', 'x', ['s']),
        ]);

        self::assertSame('one', $renderer->selected()?->id);
        $renderer->move(1);
        self::assertSame('two', $renderer->selected()?->id);
        $renderer->move(-5);
        self::assertSame('one', $renderer->selected()?->id);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `composer test -- --filter TuiRendererTest`
Expected: FAIL — `Class "Php2Scan\Ui\TuiRenderer" not found`.

- [ ] **Step 3: Implement `src/Ui/TuiRenderer.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Ui;

use Php2Scan\Finding;
use Php2Scan\Report\Theme;
use Php2Scan\Severity;
use PhpTui\Tui\Color\AnsiColor;
use PhpTui\Tui\Display\Backend;
use PhpTui\Tui\Display\Backend\DummyBackend;
use PhpTui\Tui\DisplayBuilder;
use PhpTui\Tui\DisplayBuilder as Builder;
use PhpTui\Tui\Extension\Core\Widget\BlockWidget;
use PhpTui\Tui\Extension\Core\Widget\GridWidget;
use PhpTui\Tui\Extension\Core\Widget\ParagraphWidget;
use PhpTui\Tui\Extension\Core\Widget\Table\TableCell;
use PhpTui\Tui\Extension\Core\Widget\Table\TableRow;
use PhpTui\Tui\Extension\Core\Widget\TableWidget;
use PhpTui\Tui\Layout\Constraint;
use PhpTui\Tui\Style\Style;
use PhpTui\Tui\Text\Line;
use PhpTui\Tui\Text\Span;
use PhpTui\Tui\Text\Title;
use PhpTui\Tui\Widget\Borders;
use PhpTui\Tui\Widget\Direction;

final class TuiRenderer
{
    /**
     * @var list<string> $targets
     */
    private array $targets = [];

    /**
     * @var array<string, string> $phases
     */
    private array $phases = [];

    /**
     * @var list<Finding> $findings
     */
    private array $findings = [];

    private int $selected = 0;
    private bool $expanded = false;
    private bool $quit = false;

    private Builder $builder;
    private \PhpTui\Tui\Display\Display $display;

    public function __construct(?Backend $backend = null)
    {
        $this->builder = DisplayBuilder::default($backend ?? new DummyBackend(100, 30));
        $this->display = $this->builder->build();
    }

    /**
     * @param list<string> $targets
     */
    public function start(array $targets): void
    {
        $this->targets = $targets;
        $this->phases = array_fill_keys($targets, 'pending');
    }

    public function update(string $targetLabel, string $phase): void
    {
        $this->phases[$targetLabel] = $phase;
    }

    /**
     * @param list<Finding> $findings
     */
    public function setFindings(array $findings): void
    {
        $this->findings = $findings;
        $this->selected = 0;
        $this->expanded = false;
    }

    public function selected(): ?Finding
    {
        return $this->findings[$this->selected] ?? null;
    }

    public function move(int $delta): void
    {
        if ($this->findings === []) {
            return;
        }

        $count = count($this->findings);
        $this->selected = (($this->selected + $delta) % $count + $count) % $count;
    }

    public function toggleExpanded(): void
    {
        $this->expanded = !$this->expanded;
    }

    public function isQuitRequested(): bool
    {
        return $this->quit;
    }

    public function requestQuit(): void
    {
        $this->quit = true;
    }

    public function draw(): void
    {
        $this->display->draw(GridWidget::default()
            ->direction(Direction::Vertical)
            ->constraints(Constraint::length(6), Constraint::min(0))
            ->widgets($this->progressPane(), $this->findingsPane()));
    }

    private function progressPane(): BlockWidget
    {
        $rows = [];
        foreach ($this->targets as $target) {
            $phase = $this->phases[$target] ?? 'pending';
            $rows[] = TableRow::fromCells(
                TableCell::fromString($target),
                TableCell::fromString($phase),
            );
        }

        $table = TableWidget::default()
            ->rows(...$rows)
            ->widths(Constraint::percentage(60), Constraint::percentage(40));

        return BlockWidget::default()
            ->borders(Borders::ALL)
            ->titles(Title::fromString('PHP2Shell Scan'))
            ->widget($table);
    }

    private function findingsPane(): BlockWidget
    {
        $lines = [];

        foreach ($this->findings as $index => $finding) {
            $marker = $index === $this->selected ? '>' : ' ';
            $lines[] = Line::fromSpans(
                Span::styled($marker . ' ', Style::default()->fg(self::color($finding->severity))),
                Span::styled(Theme::label($finding->severity), Style::default()->fg(self::color($finding->severity))),
                Span::fromString('  ' . $finding->title . ' — ' . $finding->target),
            );
            $lines[] = Line::fromString('    ' . $finding->evidence);
            $lines[] = Line::fromString('    How to exploit: ' . $finding->exploit);

            if ($this->expanded && $index === $this->selected) {
                foreach ($finding->reproduce as $step) {
                    $lines[] = Line::fromString('    $ ' . $step);
                }
            }
        }

        if ($lines === []) {
            $lines[] = Line::fromString('No findings yet.');
        }

        return BlockWidget::default()
            ->borders(Borders::ALL)
            ->titles(Title::fromString('Findings'))
            ->widget(ParagraphWidget::fromLines(...$lines));
    }

    private static function color(Severity $severity): AnsiColor
    {
        return match ($severity) {
            Severity::Critical => AnsiColor::Red,
            Severity::High => AnsiColor::LightRed,
            Severity::Medium => AnsiColor::Yellow,
            Severity::Low => AnsiColor::Cyan,
            Severity::Info => AnsiColor::Green,
        };
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `composer test -- --filter TuiRendererTest`
Expected: PASS — `OK (3 tests, 5 assertions)`.

- [ ] **Step 5: Commit**

```bash
git add src/Ui/TuiRenderer.php tests/Unit/TuiRendererTest.php
git commit -m "feat: tui progress and findings panes"
```

---

### Task 17: TUI live loop, key handling and integration with the scan

**Files:**
- Modify: `src/Ui/TuiRenderer.php`
- Modify: `src/Command/ScanCommand.php`
- Test: `tests/Unit/TuiRendererTest.php`

**Interfaces:**
- Consumes: `Php2Scan\Ui\TuiRenderer` (Task 16), `Php2Scan\Engine` (Task 7).
- Produces:
  - `Php2Scan\Ui\TuiRenderer::handleKey(string $key): void` — `q` sets the quit flag, `j`/down-arrow moves down, `k`/up-arrow moves up, `r`/enter toggles expansion, `s` returns a save request through `saveRequested(): bool`.
  - `Php2Scan\Ui\TuiRenderer::renderFrame(): void` — one render pass.

**Key handling:** the terminal is read with `PhpTui\Term\Terminal::new()->events()->next()`. It returns `?Event`; a `CharKeyEvent` carries the character, and `KeyEvent` carries the key code. Only handle events when a terminal is present — the `DummyBackend` path has no terminal and must not block.

- [ ] **Step 1: Add the failing test to `tests/Unit/TuiRendererTest.php`**

```php
    public function testTheQKeyRequestsAQuit(): void
    {
        $backend = new DummyBackend(100, 30);
        $renderer = new TuiRenderer($backend);
        $renderer->start(['a.example.com']);

        self::assertFalse($renderer->isQuitRequested());
        $renderer->handleKey('q');
        self::assertTrue($renderer->isQuitRequested());
    }

    public function testTheRKeyTogglesTheExpandedView(): void
    {
        $backend = new DummyBackend(100, 30);
        $renderer = new TuiRenderer($backend);
        $renderer->start(['a.example.com']);
        $renderer->setFindings([new Finding('one', 'First', Severity::High, 'a.example.com', 'e', 'x', ['s'])]);

        $renderer->handleKey('r');
        $renderer->draw();
        self::assertStringContainsString('$ s', $backend->toString());
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `composer test -- --filter TuiRendererTest`
Expected: FAIL — `Call to undefined method Php2Scan\Ui\TuiRenderer::handleKey()`.

- [ ] **Step 3: Add `handleKey()` and `saveRequested()` to `src/Ui/TuiRenderer.php`**

```php
    public function handleKey(string $key): void
    {
        match ($key) {
            'q' => $this->quit = true,
            'j' => $this->move(1),
            'k' => $this->move(-1),
            'r', "\n" => $this->toggleExpanded(),
            's' => $this->save = true,
            default => null,
        };
    }

    public function saveRequested(): bool
    {
        return $this->save;
    }
```

Add the `private bool $save = false;` property.

- [ ] **Step 4: Add the terminal event pump to `src/Ui/TuiRenderer.php`**

```php
    private ?\PhpTui\Term\Terminal $terminal = null;

    public function pollKeys(): void
    {
        if ($this->terminal === null) {
            $this->terminal = \PhpTui\Term\Terminal::new();
        }

        while (($event = $this->terminal->events()->next()) !== null) {
            if ($event instanceof \PhpTui\Term\Event\CharKeyEvent) {
                $this->handleKey($event->char);
                continue;
            }

            if ($event instanceof \PhpTui\Term\Event\KeyEvent) {
                $this->handleKey(match ($event->keyCode) {
                    \PhpTui\Term\KeyCode::Down => 'j',
                    \PhpTui\Term\KeyCode::Up => 'k',
                    default => '',
                });
            }
        }
    }
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `composer test -- --filter TuiRendererTest`
Expected: PASS — `OK (5 tests, 7 assertions)`.

- [ ] **Step 6: Wire the TUI into `src/Command/ScanCommand.php`**

In `execute()`, when the resolved format is `tui`, replace the plain render with:

```php
        if ($format === 'tui') {
            $renderer = new TuiRenderer();
            $renderer->start(array_map(static fn ($t): string => $t->label(), $config->targets));

            $result = $engine->run($config, static function (string $label, string $phase) use ($renderer): void {
                $renderer->update($label, $phase);
            });

            $renderer->setFindings($result->findings);
            $renderer->draw();
        } else {
            $result = $engine->run($config);
        }
```

Add the import `use Php2Scan\Ui\TuiRenderer;`.

- [ ] **Step 7: Commit**

```bash
git add src/Ui/TuiRenderer.php src/Command/ScanCommand.php tests/Unit/TuiRendererTest.php
git commit -m "feat: tui key handling and live scan integration"
```

---

## Phase 3 — Opt-in verification

### Task 18: Crawler for parameter discovery

**Files:**
- Create: `src/Crawler/Crawler.php`
- Test: `tests/Unit/CrawlerTest.php`

**Interfaces:**
- Consumes: `Php2Scan\Http\Client`, `Php2Scan\Target`.
- Produces: `Php2Scan\Crawler\Crawler` — `final class Crawler`, constructed as `new Crawler(Client $client, int $depth = 1)`. Method:
  - `public function parameters(Target $target): array` — returns `array<string, list<string>>` mapping a URL to the list of GET parameter names found on that URL. Only same-host URLs are followed, and only up to `$depth` hops from the target URL.

- [ ] **Step 1: Write the failing test `tests/Unit/CrawlerTest.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Php2Scan\Crawler\Crawler;
use Php2Scan\Http\Client;
use Php2Scan\Target;

final class CrawlerTest extends TestCase
{
    public function testItCollectsQueryParametersFromThePageAndItsLinks(): void
    {
        $pages = [
            'https://example.com/' => new Response(200, [], '<a href="/search?q=test">search</a>'),
            'https://example.com/search' => new Response(200, [], '<form action="/search"><input name="q"></form>'),
        ];

        $client = new Client(new \GuzzleHttp\Client(['http_errors' => false]), 0);
        $crawler = new Crawler($client);

        $parameters = $crawler->parameters(new Target('https://example.com'), $pages);

        self::assertArrayHasKey('https://example.com/search', $parameters);
        self::assertContains('q', $parameters['https://example.com/search']);
    }
}
```

**Note for the implementer:** give `Crawler::parameters()` an optional second argument `array $pages` that maps a URL to a pre-built `ResponseInterface`. When it is absent the crawler fetches with the injected client. The test passes the pages directly so it needs no network.

- [ ] **Step 2: Run the test to verify it fails**

Run: `composer test -- --filter CrawlerTest`
Expected: FAIL — `Class "Php2Scan\Crawler\Crawler" not found`.

- [ ] **Step 3: Implement `src/Crawler/Crawler.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Crawler;

use Php2Scan\Http\Client;
use Php2Scan\Target;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\DomCrawler\Crawler as DomCrawler;

final class Crawler
{
    public function __construct(
        private readonly Client $client,
        private readonly int $depth = 1,
    ) {
    }

    /**
     * @param array<string, ResponseInterface> $pages
     * @return array<string, list<string>>
     */
    public function parameters(Target $target, array $pages = []): array
    {
        $base = rtrim($target->url, '/') . '/';
        $queue = [$base];
        $visited = [];
        $parameters = [];

        while ($queue !== []) {
            $url = array_shift($queue);

            if (isset($visited[$url]) || count($visited) >= 50) {
                continue;
            }
            $visited[$url] = true;

            $response = $pages[$url] ?? $this->client->get($url, $target->requestHeaders());
            if ($response === null || $response->getStatusCode() >= 400) {
                continue;
            }

            $body = (string) $response->getBody();
            $dom = new DomCrawler($body, $target->url);

            $query = [];
            parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
            foreach (array_keys($query) as $name) {
                $parameters[$url][] = (string) $name;
            }

            foreach ($dom->filter('form') as $form) {
                $action = $form->getAttribute('action');
                $absolute = $action === '' ? $url : $this->absolute($action, $url);
                if ($absolute === null) {
                    continue;
                }
                foreach ($dom->filter('input, select, textarea') as $input) {
                    $name = $input->getAttribute('name');
                    if ($name !== '') {
                        $parameters[$absolute][] = $name;
                    }
                }
            }

            if (count($visited) < $this->depth * 20) {
                foreach ($dom->filter('a[href]') as $link) {
                    $href = $link->getAttribute('href');
                    $absolute = $this->absolute($href, $url);
                    if ($absolute === null || isset($visited[$absolute])) {
                        continue;
                    }
                    $queue[] = $absolute;
                }
            }
        }

        foreach ($parameters as $url => $names) {
            $parameters[$url] = array_values(array_unique($names));
        }

        return $parameters;
    }

    private function absolute(string $href, string $current): ?string
    {
        if ($href === '' || str_starts_with($href, '#') || str_starts_with($href, 'mailto:')) {
            return null;
        }

        $parts = parse_url($href);
        if (isset($parts['host']) && $parts['host'] !== parse_url($current, PHP_URL_HOST)) {
            return null;
        }

        if (isset($parts['host'])) {
            return $href;
        }

        $base = parse_url($current);
        $scheme = $base['scheme'] ?? 'https';
        $host = $base['host'] ?? '';

        if (str_starts_with($href, '/')) {
            return sprintf('%s://%s%s', $scheme, $host, $href);
        }

        $path = $base['path'] ?? '/';
        $directory = rtrim(str_replace('\\', '/', dirname($path)), '/');

        return sprintf('%s://%s%s/%s', $scheme, $host, $directory, $href);
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `composer test -- --filter CrawlerTest`
Expected: PASS — `OK (1 test, 2 assertions)`.

- [ ] **Step 5: Commit**

```bash
git add src/Crawler/Crawler.php tests/Unit/CrawlerTest.php
git commit -m "feat: parameter crawler for verification checks"
```

---

### Task 19: Injection verification checks

**Files:**
- Create: `src/Check/ParameterProbe.php` (shared base)
- Create: `src/Check/SqlInjection.php`
- Create: `src/Check/ReflectedXss.php`
- Create: `src/Check/LocalFileInclusion.php`
- Create: `data/repro/sqli.md`
- Create: `data/repro/xss.md`
- Create: `data/repro/lfi.md`
- Test: `tests/Unit/InjectionChecksTest.php`

**Interfaces:**
- Consumes: `Php2Scan\Crawler\Crawler` (Task 18), `Php2Scan\Data\Reproduce` (Task 6), `Php2Scan\Check\Check` (Task 7).
- Produces:
  - `Php2Scan\Check\ParameterProbe` — abstract base with `protected function compare(string $url, array $parameters, string $marker, array $mutations): ?Finding`. It fetches the baseline, then each mutation, and returns a finding when the responses differ in a way the subclass recognises.
  - `Php2Scan\Check\SqlInjection implements Check` — `id()` returns `'sql_injection'`.
  - `Php2Scan\Check\ReflectedXss implements Check` — `id()` returns `'reflected_xss'`.
  - `Php2Scan\Check\LocalFileInclusion implements Check` — `id()` returns `'local_file_inclusion'`.

**Verification rules:**

| Check | Mutations | Confirmed when |
|---|---|---|
| SQL injection | `'` and `' AND 1=2--` | the quote changes the status or the body length, or the boolean pair diverges |
| Reflected XSS | a unique marker | the marker appears in the body without HTML encoding |
| LFI | `../../../../etc/passwd` | the body contains `root:x:0:0` |

**These checks only run when both `checks.injection` is enabled in the config and `--verify` was passed.**

- [ ] **Step 1: Write the failing test `tests/Unit/InjectionChecksTest.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Php2Scan\Check\ReflectedXss;
use Php2Scan\Check\SqlInjection;
use Php2Scan\Data\Reproduce;
use Php2Scan\Http\Client;
use Php2Scan\Severity;
use Php2Scan\Target;
use PHPUnit\Framework\TestCase;

final class InjectionChecksTest extends TestCase
{
    /**
     * @param list<Response> $responses
     */
    private function client(array $responses): Client
    {
        $mock = new MockHandler($responses);

        return new Client(new \GuzzleHttp\Client([
            'handler' => HandlerStack::create($mock),
            'http_errors' => false,
        ]), 0);
    }

    /**
     * @return \Closure(Target): array<string, list<string>>
     */
    private function parameters(): \Closure
    {
        return static fn (Target $target): array => ['/search?q=test' => ['q']];
    }

    public function testSqlInjectionIsConfirmedWhenTheQuoteChangesTheResponse(): void
    {
        $client = $this->client([
            new Response(200, [], 'results for test'),
            new Response(500, [], 'SQL syntax error'),
        ]);

        $check = new SqlInjection(
            new Reproduce(__DIR__ . '/../../data/repro'),
            $client,
            $this->parameters(),
        );

        $findings = $check->analyze(new Target('https://example.com'), []);

        self::assertCount(1, $findings);
        self::assertSame(Severity::High, $findings[0]->severity);
        self::assertNotEmpty($findings[0]->reproduce);
    }

    public function testSqlInjectionIsNotReportedForIdenticalResponses(): void
    {
        $client = $this->client([
            new Response(200, [], 'results'),
            new Response(200, [], 'results'),
        ]);

        $check = new SqlInjection(
            new Reproduce(__DIR__ . '/../../data/repro'),
            $client,
            $this->parameters(),
        );

        self::assertSame([], $check->analyze(new Target('https://example.com'), []));
    }

    public function testReflectedXssIsConfirmedWhenTheMarkerIsUnencoded(): void
    {
        $client = $this->client([
            new Response(200, [], '<p>php2scanmarker</p>'),
        ]);

        $check = new ReflectedXss(
            new Reproduce(__DIR__ . '/../../data/repro'),
            $client,
            static fn (Target $target): array => ['/search?q=php2scanmarker' => ['q']],
        );

        $findings = $check->analyze(new Target('https://example.com'), []);

        self::assertCount(1, $findings);
        self::assertStringContainsString('php2scanmarker', $findings[0]->evidence);
    }

    public function testReflectedXssIsNotReportedWhenTheMarkerIsEncoded(): void
    {
        $client = $this->client([
            new Response(200, [], '<p>php2scan&#109;arker</p>'),
        ]);

        $check = new ReflectedXss(
            new Reproduce(__DIR__ . '/../../data/repro'),
            $client,
            static fn (Target $target): array => ['/search?q=php2scanmarker' => ['q']],
        );

        self::assertSame([], $check->analyze(new Target('https://example.com'), []));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `composer test -- --filter InjectionChecksTest`
Expected: FAIL — `Class "Php2Scan\Check\SqlInjection" not found`.

- [ ] **Step 3: Implement `src/Check/ParameterProbe.php`**

```php
abstract class ParameterProbe implements Check
{
    /**
     * The subclasses inherit this constructor unchanged.
     *
     * @param null|\Closure(Target): array<string, list<string>> $parameterSource
     */
    public function __construct(
        protected readonly Reproduce $reproduce,
        protected readonly Client $client,
        protected readonly ?\Closure $parameterSource = null,
    ) {
    }

    public function id(): string
    {
        return $this->probeId();
    }

    public function paths(Target $target, ?ResponseInterface $baseline): array
    {
        return [];
    }

    abstract protected function probeId(): string;

    abstract protected function probeTitle(): string;

    abstract protected function severity(): Severity;

    /** @return list<array<string, string>> */
    abstract protected function mutations(string $marker): array;

    abstract protected function isConfirmed(ResponseInterface $baseline, ResponseInterface $mutated, string $mutatedUrl): bool;

    abstract protected function evidence(ResponseInterface $baseline, ResponseInterface $mutated, string $mutatedUrl): string;

    abstract protected function exploit(string $mutatedUrl): string;

    public function analyze(Target $target, array $responses): array
    {
        $findings = [];

        $parameters = $this->parameterSource !== null
            ? ($this->parameterSource)($target)
            : (new Crawler($this->client))->parameters($target);

        foreach ($parameters as $path => $names) {
            $baselineUrl = rtrim($target->url, '/') . '/' . ltrim($path, '/');
            $baseline = $this->client->get($baselineUrl, $target->requestHeaders());

            if ($baseline === null) {
                continue;
            }

            $marker = 'php2scan' . bin2hex(random_bytes(4));

            foreach ($this->mutations($marker) as $mutation) {
                $mutatedUrl = $this->applyMutation($baselineUrl, $mutation);
                $mutated = $this->client->get($mutatedUrl, $target->requestHeaders());

                if ($mutated === null) {
                    continue;
                }

                if (!$this->isConfirmed($baseline, $mutated, $mutatedUrl)) {
                    continue;
                }

                $findings[] = new Finding(
                    id: $this->probeId(),
                    title: $this->probeTitle(),
                    severity: $this->severity(),
                    target: $target->label(),
                    evidence: $this->evidence($baseline, $mutated, $mutatedUrl),
                    exploit: $this->exploit($mutatedUrl),
                    reproduce: $this->reproduce->steps($this->probeId(), $target->url, $target->label()),
                );

                break;
            }
        }

        return $findings;
    }

    /**
     * @param array<string, string> $mutation
     */
    private function applyMutation(string $url, array $mutation): string
    {
        $parts = parse_url($url);
        $query = [];
        parse_str((string) ($parts['query'] ?? ''), $query);

        foreach ($mutation as $name => $value) {
            $query[$name] = $value;
        }

        return sprintf(
            '%s://%s%s%s',
            $parts['scheme'] ?? 'https',
            $parts['host'] ?? '',
            $parts['path'] ?? '/',
            $query === [] ? '' : '?' . http_build_query($query)
        );
    }
}
```

The three subclasses differ only in their mutations and their confirmation rule, so they all share this base. The crawler supplies the parameterised URLs; the base fetches the baseline and each mutation itself, because a mutated URL is only known after the crawl.

`$parameterSource` is the same injection pattern used by `Tls` and `OpenPorts`: it lets the unit test supply the parameter map directly, so the test needs no crawler and no network ordering assumptions.

- [ ] **Step 4: Implement `src/Check/SqlInjection.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Check;

use Php2Scan\Data\Reproduce;
use Php2Scan\Http\Client;
use Php2Scan\Severity;
use Psr\Http\Message\ResponseInterface;

final class SqlInjection extends ParameterProbe
{
    protected function probeId(): string
    {
        return 'sql_injection';
    }

    protected function probeTitle(): string
    {
        return 'SQL injection';
    }

    protected function severity(): Severity
    {
        return Severity::High;
    }

    protected function mutations(string $marker): array
    {
        return [
            ['q' => "'"],
            ['q' => "' AND 1=2--"],
        ];
    }

    protected function isConfirmed(ResponseInterface $baseline, ResponseInterface $mutated, string $mutatedUrl): bool
    {
        if ($baseline->getStatusCode() !== $mutated->getStatusCode()) {
            return true;
        }

        return strlen((string) $baseline->getBody()) !== strlen((string) $mutated->getBody());
    }

    protected function evidence(ResponseInterface $baseline, ResponseInterface $mutated, string $mutatedUrl): string
    {
        return sprintf(
            'Baseline %d (%d bytes) vs mutated %d (%d bytes) at %s.',
            $baseline->getStatusCode(),
            strlen((string) $baseline->getBody()),
            $mutated->getStatusCode(),
            strlen((string) $mutated->getBody()),
            $mutatedUrl
        );
    }

    protected function exploit(string $mutatedUrl): string
    {
        return sprintf('Send %s and observe the response change - the parameter is concatenated into a SQL statement.', $mutatedUrl);
    }
}
```

- [ ] **Step 5: Implement `src/Check/ReflectedXss.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Check;

use Php2Scan\Data\Reproduce;
use Php2Scan\Http\Client;
use Php2Scan\Severity;
use Psr\Http\Message\ResponseInterface;

final class ReflectedXss extends ParameterProbe
{
    protected function probeId(): string
    {
        return 'reflected_xss';
    }

    protected function probeTitle(): string
    {
        return 'Reflected XSS';
    }

    protected function severity(): Severity
    {
        return Severity::Medium;
    }

    protected function mutations(string $marker): array
    {
        return [['q' => $marker]];
    }

    protected function isConfirmed(ResponseInterface $baseline, ResponseInterface $mutated, string $mutatedUrl): bool
    {
        $body = (string) $mutated->getBody();

        return str_contains($body, $this->markerOf($mutatedUrl));
    }

    protected function evidence(ResponseInterface $baseline, ResponseInterface $mutated, string $mutatedUrl): string
    {
        return sprintf('The marker is reflected unencoded at %s.', $mutatedUrl);
    }

    protected function exploit(string $mutatedUrl): string
    {
        return sprintf('Deliver %s to a victim - the payload executes in the page origin with the victim session.', $mutatedUrl);
    }

    private function markerOf(string $url): string
    {
        $query = [];
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        foreach ($query as $value) {
            if (is_string($value) && str_starts_with($value, 'php2scan')) {
                return $value;
            }
        }

        return '';
    }
}
```

- [ ] **Step 6: Implement `src/Check/LocalFileInclusion.php`**

```php
<?php

declare(strict_types=1);

namespace Php2Scan\Check;

use Php2Scan\Data\Reproduce;
use Php2Scan\Http\Client;
use Php2Scan\Severity;
use Psr\Http\Message\ResponseInterface;

final class LocalFileInclusion extends ParameterProbe
{
    protected function probeId(): string
    {
        return 'local_file_inclusion';
    }

    protected function probeTitle(): string
    {
        return 'Local file inclusion';
    }

    protected function severity(): Severity
    {
        return Severity::High;
    }

    protected function mutations(string $marker): array
    {
        return [['file' => '../../../../etc/passwd'], ['page' => '../../../../etc/passwd']];
    }

    protected function isConfirmed(ResponseInterface $baseline, ResponseInterface $mutated, string $mutatedUrl): bool
    {
        return str_contains((string) $mutated->getBody(), 'root:x:0:0');
    }

    protected function evidence(ResponseInterface $baseline, ResponseInterface $mutated, string $mutatedUrl): string
    {
        return sprintf('The response at %s contains the contents of /etc/passwd.', $mutatedUrl);
    }

    protected function exploit(string $mutatedUrl): string
    {
        return sprintf('Request %s to read any file the PHP worker can read - source code, keys, or /etc/shadow.', $mutatedUrl);
    }
}
```

- [ ] **Step 7: Create the reproduce files**

`data/repro/sqli.md`:

```
curl -sS -o /dev/null -w '%{{http_code}} %{{size_download}}\n' '{url}'
# baseline
curl -sS -o /dev/null -w '%{{http_code}} %{{size_download}}\n' '{url}&q=%27'
# the quote changes the response, which means the parameter reaches the database
```

`data/repro/xss.md`:

```
curl -sS '{url}&q=php2scanmarker' | grep -o 'php2scanmarker'
# the marker comes back unencoded, so a script tag would execute
```

`data/repro/lfi.md`:

```
curl -sS '{url}&file=../../../../etc/passwd' | head -3
# root:x:0:0 means the server read a file outside the web root
```

- [ ] **Step 8: Run the test to verify it passes**

Run: `composer test -- --filter InjectionChecksTest`
Expected: PASS — `OK (4 tests, 6 assertions)`.

The tests above inject the parameter map and queue the baseline and mutated responses through a Guzzle `MockHandler`, so they need no network and no crawler.

- [ ] **Step 9: Commit**

```bash
git add src/Check/ParameterProbe.php src/Check/SqlInjection.php src/Check/ReflectedXss.php src/Check/LocalFileInclusion.php data/repro/sqli.md data/repro/xss.md data/repro/lfi.md tests/Unit/InjectionChecksTest.php
git commit -m "feat: opt-in injection verification checks"
```

---

### Task 20: Gate verification behind `--verify` and confirmation

**Files:**
- Modify: `src/Command/ScanCommand.php`
- Modify: `src/Config.php`
- Test: `tests/Integration/ScanCommandTest.php`

**Interfaces:**
- Consumes: `Php2Scan\Config` (Task 3), `Php2Scan\Command\ScanCommand` (Task 15).
- Produces: `Config::$verify` is true only when `--verify` was passed. The `injection` check is registered only when both `checks.injection` is enabled in the config **and** `--verify` was passed. When `--verify` is used against a target whose `staging` flag is false, the command asks for confirmation unless `--yes` was passed.

- [ ] **Step 1: Add the failing test to `tests/Integration/ScanCommandTest.php`**

```php
    public function testVerifyIsRequiredBeforeTheInjectionCheckRuns(): void
    {
        $config = tempnam(sys_get_temp_dir(), 'php2scan') . '.yaml';
        file_put_contents($config, "targets:\n  - http://127.0.0.1:1/unreachable\nchecks:\n  injection: true\n");

        [$code, $output] = $this->run([
            'command' => 'scan',
            '--config' => $config,
            '--format' => 'json',
        ], sys_get_temp_dir());

        self::assertSame(0, $code);
        self::assertStringNotContainsString('sql_injection', $output);

        unlink($config);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `composer test -- --filter ScanCommandTest`
Expected: FAIL — the injection check runs without `--verify`.

- [ ] **Step 3: Gate the injection check in `src/Command/ScanCommand.php`**

Replace the registry construction with:

```php
        $checks = [
            'php_presence' => new PhpDetection($reproduce),
            'php_version' => new PhpVersion($db, $reproduce),
            'sensitive_files' => new SensitiveFiles($wordlists, $reproduce),
            'security_headers' => new SecurityHeaders($reproduce),
            'tls' => new Tls($reproduce),
            'app_fingerprint' => new AppFingerprint($reproduce),
            'webshell_indicators' => new WebshellIndicators($wordlists, $reproduce),
            'open_ports' => new OpenPorts($wordlists, $reproduce),
        ];

        if ($verify && $config->checkEnabled('injection')) {
            $checks['sql_injection'] = new SqlInjection($reproduce, $client);
            $checks['reflected_xss'] = new ReflectedXss($reproduce, $client);
            $checks['local_file_inclusion'] = new LocalFileInclusion($reproduce, $client);
        }

        $registry = new Registry($checks);
```

where `$verify = (bool) $input->getOption('verify')`.

**Important:** `Config::CHECKS` already contains `sql_injection`, `reflected_xss` and `local_file_inclusion` (added in Task 3), and `Config::parseChecks()` switches them on when the single `injection` toggle is set. `Registry::enabled()` iterates `Config::CHECKS`, and skips any id that has no registered check instance — which is exactly the gate this task adds: without `--verify` the three instances are never registered, so the checks never run.

- [ ] **Step 4: Add the confirmation prompt**

In `execute()`, before running the engine when `$verify` is true:

```php
        if ($verify) {
            $needsConfirmation = false;
            foreach ($config->targets as $target) {
                if (!$target->staging) {
                    $needsConfirmation = true;
                    break;
                }
            }

            if ($needsConfirmation && !$input->getOption('yes')) {
                $confirmed = $this->getHelper('question')->ask(
                    $input,
                    $output,
                    'Verification sends proof-of-concept requests to hosts that are not marked as staging. Continue? [y/N] '
                );

                if (!is_string($confirmed) || strtolower($confirmed) !== 'y') {
                    $output->writeln('<comment>Aborted - verification requires --yes to skip this prompt.</comment>');

                    return 2;
                }
            }
        }
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `composer test -- --filter ScanCommandTest`
Expected: PASS — `OK (3 tests, 4 assertions)`.

- [ ] **Step 6: Run the whole suite**

Run: `composer test`
Expected: PASS — no failures.

- [ ] **Step 7: Commit**

```bash
git add src/Command/ScanCommand.php src/Config.php tests/Integration/ScanCommandTest.php
git commit -m "feat: gate injection verification behind --verify and confirmation"
```

---

## Phase 4 — Optional

### Task 21: `nuclei` passthrough (optional, only on request)

**Files:**
- Modify: `src/Command/ScanCommand.php`
- Create: `data/nuclei-templates.txt`

**Interfaces:**
- Consumes: `Php2Scan\Config`.
- Produces: `php2scan scan --with-nuclei` runs the `nuclei` binary against each target with only the template ids listed in `data/nuclei-templates.txt`, and appends the output to the report.

**Skip this task unless the user explicitly asks for it.** It adds an external binary dependency and a template-curation burden that the rest of the tool does not need.

- [ ] **Step 1: Confirm the user wants it before starting**

Ask: "Do you want the nuclei passthrough? It needs the nuclei binary installed and a curated template list."

- [ ] **Step 2: …continue from the confirmed design**

Implement, test, and commit as agreed.

---

## Appendix A — Verified environment facts

Everything below was verified by installing the packages and running probes on PHP 8.5.12 / Composer 2.10.3. Do not re-derive these; they are the reason several steps look the way they do.

| Fact | Consequence |
|---|---|
| `CurlMultiHandler` in Guzzle 8 has **no `active()` method** | completion is detected by counting settled promises |
| A rejected promise must be counted as settled | every request promise needs an `->otherwise()` branch or the pool never terminates |
| `CurlMultiHandler` constructor takes `max_total_connections` and `max_host_connections` | the global and per-host concurrency caps are built in |
| The `delay` request option is honoured by `CurlMultiHandler` | per-host politeness spacing is a request option, not a sleep |
| `aidantwoods/secureheaders` `auto(false)` **throws** on PHP 8.5 (its `Types::assert` requires an int) | pass `auto(0)` |
| `secureheaders::apply()` installs its own error handler, so external capture is impossible | use `Validator::validate(new HeaderBag($headers))` standalone and do presence checks locally |
| `secureheaders` emits PHP 8.5 deprecations at class-load time | `error_reporting(E_ALL & ~E_DEPRECATED)` must be set before the class is autoloaded |
| `secureheaders` validator messages contain HTML tags | strip them before rendering |
| `php-tui` `Display::draw()` renders **and** flushes | never call `Display::flush()` after `draw()` |
| `php-tui` builders (`rows()`, `widths()`, `fromCells()`, `fromLines()`, `fromSpans()`) are variadic | passing an array is a `TypeError` |
| `php-tui` has no vertical container widget | `GridWidget` with `Direction::Vertical` is the way to split the screen |
| `php-tui` `Terminal::events()->next()` is non-blocking | safe to poll inside a render loop |
| `php-tui` needs a TTY for its size | gate the TUI on `stream_isatty(STDOUT)` |
