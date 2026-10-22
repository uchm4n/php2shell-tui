<?php

declare(strict_types=1);

namespace Php2Scan\Check;

use Php2Scan\Severity;
use Psr\Http\Message\ResponseInterface;

final class SqlInjection extends ParameterProbe
{
    protected function probeId(): string
    {
        return 'sql_injection';
    }

    protected function probeTitle(): string
    {
        return 'SQL injection';
    }

    protected function severity(): Severity
    {
        return Severity::High;
    }

    protected function payloads(string $marker): array
    {
        return ["'", "' AND 1=2--"];
    }

    protected function isConfirmed(ResponseInterface $baseline, ResponseInterface $mutated, string $mutatedUrl, string $marker): bool
    {
        if ($baseline->getStatusCode() !== $mutated->getStatusCode()) {
            return true;
        }

        return strlen((string) $baseline->getBody()) !== strlen((string) $mutated->getBody());
    }

    protected function evidence(ResponseInterface $baseline, ResponseInterface $mutated, string $mutatedUrl): string
    {
        return sprintf(
            'Baseline %d (%d bytes) vs payload response %d (%d bytes) at %s.',
            $baseline->getStatusCode(),
            strlen((string) $baseline->getBody()),
            $mutated->getStatusCode(),
            strlen((string) $mutated->getBody()),
            $mutatedUrl
        );
    }

    protected function exploit(string $mutatedUrl): string
    {
        return sprintf('Send %s and observe the response change - the parameter is concatenated into a SQL statement.', $mutatedUrl);
    }
}
