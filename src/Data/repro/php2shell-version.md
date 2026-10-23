curl -sI {url}/ | grep -iE 'x-powered-by|^server:'
# confirms the PHP version the server advertises

ssh {host} 'php -v; php -i | grep -E "memory_limit|opcache.enable"'
# confirms the real runtime version on the host itself

ssh {host} 'rpm -q php 2>/dev/null || dpkg-query -W php 2>/dev/null || apk info -v php 2>/dev/null'
# the package revision - a vendor backport can carry the fix without the version changing

# CVE-2026-109618 / CVE-2026-109619: the public chain is version- and build-specific.
# A successful PoC may return 200, 500, or a worker crash; none is proof by itself.
# Only a unique command-execution proof counts. The verified public chain is Apache prefork + mod_php;
# FPM behavior differs and is not verified by this tool.
# See https://www.wiz.io/blog/php2shell-php-rce and the scanner's full-proof check.
# Run this against a staging copy, never against production.
