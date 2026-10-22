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
