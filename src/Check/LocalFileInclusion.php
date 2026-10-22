<?php

declare(strict_types=1);

namespace Php2Scan\Check;

use Php2Scan\Severity;
use Psr\Http\Message\ResponseInterface;

final class LocalFileInclusion extends ParameterProbe
{
    protected function probeId(): string
    {
        return 'local_file_inclusion';
    }

    protected function probeTitle(): string
    {
        return 'Local file inclusion';
    }

    protected function severity(): Severity
    {
        return Severity::High;
    }

    protected function payloads(string $marker): array
    {
        return ['../../../../etc/passwd'];
    }

    protected function isConfirmed(ResponseInterface $baseline, ResponseInterface $mutated, string $mutatedUrl, string $marker): bool
    {
        return str_contains((string) $mutated->getBody(), 'root:x:0:0');
    }

    protected function evidence(ResponseInterface $baseline, ResponseInterface $mutated, string $mutatedUrl): string
    {
        return sprintf('The response at %s contains the contents of /etc/passwd.', $mutatedUrl);
    }

    protected function exploit(string $mutatedUrl): string
    {
        return sprintf('Request %s to read any file the PHP worker can read - source code, keys, or /etc/shadow.', $mutatedUrl);
    }
}
