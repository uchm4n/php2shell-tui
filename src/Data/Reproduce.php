<?php

declare(strict_types=1);

namespace Php2ShellTui\Data;

final class Reproduce
{
    public function __construct(private readonly string $reproDir)
    {
    }

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
}
