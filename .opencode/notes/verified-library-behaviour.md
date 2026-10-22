# Verified library behaviour

Probed against the exact versions installed on PHP 8.5.12 / Composer 2.10.3.
These are established facts, not guesses — re-derive only if a dependency version changes.

## guzzlehttp/guzzle 8.3

- `CurlMultiHandler` has **no `active()` method**. Detect completion by counting settled promises.
- A **rejected** promise must count as settled, otherwise the pool loop never terminates on a
  connection-refused or DNS-failure target. Both branches of `->then()` must increment the counter.
- Constructor options: `handle_factory`, `max_host_connections`, `max_total_connections`,
  `multiplex`, `options`, `select_timeout`, `transport_sharing`. Any other name throws.
- The `delay` request option (milliseconds) is honoured — the transfer is not attached until the
  delay elapses. Use it for per-host politeness spacing instead of `usleep()`.
- `tick()` does **not** block while a transfer is waiting for its `delay` to elapse, so a `tick()`-only
  loop busy-spins and can give up before delayed transfers ever start. Waiting on the request promise
  (`$promise->wait()`) drives the handler (`executeUntil`) until that transfer settles and honours the
  delay; the other transfers keep running meanwhile.
- `allow_redirects` accepts an `on_redirect` callback, but Guzzle 8 **ignores its return value** — the
  callback is an observer only, and returning `false` does *not* stop the chain. To refuse a redirect
  that leaves the allowlisted host, throw from the callback (that aborts the chain) and restore the 3xx
  response from the rejection.
- `Client::prepareDefaults()` rejects a `delay` that is not a finite non-negative number.

## aidantwoods/secureheaders 2.0.1 (unmaintained since 2017)

- `SecureHeaders::auto(false)` **throws** on PHP 8.5 — its `Types::assert()` requires an `int`.
  Pass `auto(0)`.
- `SecureHeaders::apply()` installs its own error handler before triggering its errors, so an
  external error handler can never capture them. **Do not use `apply()` for auditing.**
- Use `Aidantwoods\SecureHeaders\Validator::validate(new HeaderBag($headers))` instead — it returns
  `Error[]` and each `Error::getMessage()` is capturable. The messages contain HTML tags; strip them.
- `HeaderBag::__construct(array $headers)` takes a plain header map.
- The package emits PHP 8.5 deprecations at **class-load time** (implicitly nullable parameters,
  `${var}` interpolation). Set `error_reporting(E_ALL & ~E_DEPRECATED)` *before* the class is
  autoloaded, in both `bin/php2scan` and the PHPUnit bootstrap.

## php-tui/php-tui 0.2.1

- `Display::draw(Widget)` renders **and** flushes. Calling `Display::flush()` afterwards diffs
  against a swapped buffer and **blanks the screen**. Never call it separately.
- `Display::insertBefore(int $height, Widget)` only works with the `inline()` viewport.
- Builders are **variadic**, not array-taking: `TableWidget::rows(...)`, `->widths(...)`,
  `TableRow::fromCells(...)`, `ParagraphWidget::fromLines(...)`, `Line::fromSpans(...)`.
  Passing an array is a `TypeError`.
- `TableRow::fromCells()` takes `TableCell` objects — `TableCell::fromString('x')`.
- `Line::fromString()`, `Span::fromString()`, `Span::styled($s, Style::default()->fg(AnsiColor::Yellow))`.
  `Style::fg()` takes a `Color`, not a string; `AnsiColor::fromName('yellow')` or the enum cases.
- `BlockWidget::default()->borders(Borders::ALL)->titles(Title::fromString('…'))->widget($inner)`.
- There is **no vertical container widget**. `GridWidget::default()->direction(Direction::Vertical)
  ->constraints(Constraint::length(6), Constraint::min(0))->widgets($a, $b)` is the way to split.
- `Terminal::new()->events()->next()` is **non-blocking** (`StreamReader` sets STDIN non-blocking),
  so it is safe to poll inside a render loop.
- Terminal size comes from `stty` with an env-var fallback → gate the TUI on `stream_isatty(STDOUT)`.
- `DummyBackend($w, $h)` with `toString()` / `toLines()` renders without a terminal — use it in tests.

## symfony/dom-crawler 7

- `new DomCrawler($html, $baseUri)` then `->filter('a[href]')` / `->filter('form')` / `->filter('input')`.
