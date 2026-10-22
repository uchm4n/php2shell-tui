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
