<?php

declare(strict_types=1);

namespace Php2ShellTui\Poc;

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
    ) {
        if ($this->workers !== null && ($this->workers < 1 || $this->workers > $this->maxWorkers)) {
            throw new \InvalidArgumentException(sprintf(
                'The worker count must be between 1 and %d; got %d.',
                $this->maxWorkers,
                $this->workers,
            ));
        }

        if ($this->memoryLimitMb !== null && $this->memoryLimitMb < 1) {
            throw new \InvalidArgumentException('The memory limit must be a positive number of MiB.');
        }

        if ($this->timeout < 1 || $this->requestTimeout < 1 || $this->retries < 1) {
            throw new \InvalidArgumentException('The PoC timeout, request timeout, and retry count must be positive.');
        }

        if ($this->maxWorkers < 1) {
            throw new \InvalidArgumentException('The maximum worker count must be positive.');
        }
    }

    public function withMemoryLimit(int $memoryLimitMb): self
    {
        return new self(
            profile: $this->profile,
            version: $this->version,
            arch: $this->arch,
            workers: $this->workers,
            memoryLimitMb: $memoryLimitMb,
            timeout: $this->timeout,
            requestTimeout: $this->requestTimeout,
            retries: $this->retries,
            maxWorkers: $this->maxWorkers,
        );
    }
}
