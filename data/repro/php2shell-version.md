curl -sI {url}/ | grep -iE 'x-powered-by|^server:'
# confirms the PHP version the server advertises

ssh {host} 'php -v; php -i | grep -E "memory_limit|opcache.enable"'
# confirms the real runtime version on the host itself

ssh {host} 'rpm -q php 2>/dev/null || dpkg-query -W php 2>/dev/null || apk info -v php 2>/dev/null'
# the package revision - a vendor backport can carry the fix without the version changing

# CVE-2026-109618 OOM trigger - the bytes are version- and build-specific.
# Take them from the published research: https://www.wiz.io/blog/php2shell-php-rce
# Expected effect: the FPM worker dies and the request returns 502.
# Run this against a staging copy, never against production.
