<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Metadata;

use Beffroi\Core\Exception\InvalidArgumentException;
use function sprintf;

final readonly class PublishedMetadata
{
    public const string CONTENT_TYPE = 'application/samlmetadata+xml';

    /**
     * @var array<string, string>
     */
    public array $headers;

    /**
     * @param int $maxAge in seconds
     *
     * @throws InvalidArgumentException when the lifetime is not a number of seconds
     */
    public function __construct(
        public string $document,
        int $maxAge,
    ) {
        self::assertCacheLifetime($maxAge);
        $this->headers = [
            'Cache-Control' => sprintf('public, max-age=%d', $maxAge),
        ];
    }

    /**
     * @throws InvalidArgumentException when the lifetime is not a number of seconds
     */
    public static function assertCacheLifetime(int $maxAge): void
    {
        if ($maxAge < 0) {
            throw new InvalidArgumentException('The cache lifetime of the metadata is a number of seconds (spec/saml.md section 6.1 step 6).');
        }
    }

    /**
     * S-12: a service provider that honours the cacheDuration has the next certificate before the staged key signs.
     *
     * @param int $cacheDuration in seconds
     * @param int $stagingDelay in seconds
     *
     * @throws InvalidArgumentException when the cacheDuration is under a second or not under the staging delay
     */
    public static function assertCacheDuration(int $cacheDuration, int $stagingDelay): void
    {
        if ($cacheDuration < 1) {
            throw new InvalidArgumentException('The cacheDuration of the metadata is a number of seconds, one at least (spec/saml.md S-12).');
        }
        if ($cacheDuration >= $stagingDelay) {
            throw new InvalidArgumentException(sprintf(
                'The cacheDuration of the metadata, %d s, is shorter than the staging delay of a SAML key, %d s, or a service provider that honours it meets the next key before its certificate (spec/saml.md S-12).',
                $cacheDuration,
                $stagingDelay,
            ));
        }
    }
}
