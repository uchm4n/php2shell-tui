<?php

declare(strict_types=1);

namespace Php2ShellTui;

use Php2ShellTui\Check\PhpDetection;
use Psr\Http\Message\ResponseInterface;

final class PhpFingerprint
{
    /**
     * @param array<string, ResponseInterface> $responses
     * @param list<array{version: string, source: string, confidence: string}> $versions
     * @param null|array{url: string, ini: array<string, string>, sapi: ?string} $phpinfo
     */
    private function __construct(
        private readonly array $responses,
        private readonly array $versions,
        private readonly ?array $phpinfo,
        private readonly ?string $sapi,
        private readonly ?string $serverOs,
        private readonly bool $hasPhpSignal,
    ) {
    }

    /**
     * @param array<string, ResponseInterface> $responses
     */
    public static function fromResponses(array $responses): self
    {
        $baseline = $responses['/'] ?? null;
        $versions = [];
        $seen = [];
        $server = $baseline?->getHeaderLine('Server') ?? '';
        $poweredBy = $baseline?->getHeaderLine('X-Powered-By') ?? '';
        $versionPattern = '/PHP[ \/](\d+\.\d+(?:\.\d+)?[A-Za-z0-9.\-]*)/i';
        $bodyVersionPattern = '/PHP Version\s+(\d+\.\d+(?:\.\d+)?[A-Za-z0-9.\-]*)/i';

        foreach ([['X-Powered-By', $poweredBy, 'high'], ['Server', $server, 'medium']] as [$source, $value, $confidence]) {
            if ($value === '') {
                continue;
            }

            if (preg_match_all($versionPattern, $value, $matches) > 0) {
                foreach ($matches[1] as $version) {
                    $key = $version . '|' . $source;
                    if (!isset($seen[$key])) {
                        $versions[] = ['version' => $version, 'source' => $source, 'confidence' => $confidence];
                        $seen[$key] = true;
                    }
                }
            }
        }

        foreach ($responses as $url => $response) {
            if ($response->getStatusCode() !== 200) {
                continue;
            }

            $body = self::body($response);
            $source = $url === '/' ? 'body' : (string) $url;
            $confidence = $url === '/' ? 'low' : 'medium';

            foreach ([$versionPattern, $bodyVersionPattern] as $pattern) {
                if (preg_match_all($pattern, $body, $matches) === 0) {
                    continue;
                }

                foreach ($matches[1] as $version) {
                    $key = $version . '|' . $source;
                    if (!isset($seen[$key])) {
                        $versions[] = ['version' => $version, 'source' => $source, 'confidence' => $confidence];
                        $seen[$key] = true;
                    }
                }
            }
        }

        $phpinfo = self::findPhpinfo($responses);

        $sapi = $phpinfo['sapi'] ?? null;
        if ($sapi === null) {
            $lowerServer = strtolower($server);
            $hasPhp = stripos($poweredBy, 'PHP') !== false || str_contains(strtolower($server), 'php');

            if ($hasPhp && str_contains($lowerServer, 'apache')) {
                $sapi = 'inferred: mod_php';
            } elseif ($hasPhp && str_contains($lowerServer, 'nginx')) {
                $sapi = 'inferred: fpm';
            }
        }

        return new self(
            responses: $responses,
            versions: $versions,
            phpinfo: $phpinfo,
            sapi: $sapi,
            serverOs: self::detectServerOs($server),
            hasPhpSignal: $baseline !== null && PhpDetection::signals($baseline) !== [],
        );
    }

    /**
     * @return list<array{version: string, source: string, confidence: string}>
     */
    public function versions(): array
    {
        return $this->versions;
    }

    /**
     * @return null|array{url: string, ini: array<string, string>, sapi: ?string}
     */
    public function phpinfo(): ?array
    {
        return $this->phpinfo;
    }

    public function sapi(): ?string
    {
        return $this->sapi;
    }

    public function serverOs(): ?string
    {
        return $this->serverOs;
    }

    public function hasPhpSignal(): bool
    {
        return $this->hasPhpSignal;
    }

    /**
     * @return array<string, string>
     */
    public function ini(): array
    {
        return $this->phpinfo['ini'] ?? [];
    }

    /**
     * @return list<string>
     */
    public static function paths(): array
    {
        return ['/', '/phpinfo.php', '/info.php'];
    }

    /**
     * @param array<string, ResponseInterface> $responses
     * @return null|array{url: string, ini: array<string, string>, sapi: ?string}
     */
    private static function findPhpinfo(array $responses): ?array
    {
        foreach ($responses as $url => $response) {
            $body = self::body($response);
            if (!str_contains($body, 'PHP Version')) {
                continue;
            }

            $rows = [];
            if (preg_match_all(
                '/<td[^>]*class="e"[^>]*>(.*?)<\/td>\s*<td[^>]*class="v"[^>]*>(.*?)<\/td>/s',
                $body,
                $matches,
                PREG_SET_ORDER,
            ) > 0) {
                foreach ($matches as $match) {
                    $name = strtolower(trim(strip_tags($match[1])));
                    $value = trim(strip_tags($match[2]));
                    if ($name !== '') {
                        $rows[$name] = $value;
                    }
                }
            }

            if ($rows === []) {
                continue;
            }

            if (preg_match('/PHP Version\s+(\d+\.\d+(?:\.\d+)?[A-Za-z0-9.\-]*)/i', $body, $version) === 1) {
                $rows['php version'] = $version[1];
            }

            return [
                'url' => (string) $url,
                'ini' => $rows,
                'sapi' => $rows['server api'] ?? null,
            ];
        }

        return null;
    }

    private static function body(ResponseInterface $response): string
    {
        $body = $response->getBody();
        if ($body->isSeekable()) {
            $body->rewind();
        }

        $content = (string) $body;

        if ($body->isSeekable()) {
            $body->rewind();
        }

        return $content;
    }

    private static function detectServerOs(string $server): ?string
    {
        $server = strtolower($server);

        foreach ([
            'debian' => ['debian', 'bookworm', 'bullseye', 'buster', 'trixie'],
            'ubuntu' => ['ubuntu'],
            'alpine' => ['alpine'],
            'fedora' => ['fedora'],
            'centos' => ['centos'],
            'rhel' => ['rhel', 'red hat'],
            'amazon linux' => ['amazon linux'],
            'suse' => ['suse'],
            'arch linux' => ['arch linux'],
        ] as $os => $tokens) {
            foreach ($tokens as $token) {
                if (str_contains($server, $token)) {
                    return $os;
                }
            }
        }

        return null;
    }
}
