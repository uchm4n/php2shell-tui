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
