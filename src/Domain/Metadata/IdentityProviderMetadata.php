<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Metadata;

use Beffroi\Core\Exception\InvalidArgumentException;
use function sprintf;

/**
 * The answer of the metadata endpoint of the identity provider of a tenant (spec/saml.md section 6.1 step 6): the
 * serialized md:EntityDescriptor, its media type, and how long a cache may hold it, the max-age the staging window of
 * a key derives from, so that no cached copy is older than that window (S-2).
 */
final readonly class IdentityProviderMetadata
{
    /**
     * The media type of SAML metadata.
     */
    public const string CONTENT_TYPE = 'application/samlmetadata+xml';

    /**
     * @var array<string, string>
     */
    public array $headers;

    /**
     * @param int $maxAge how long a cache may hold the document, in seconds
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
     * The rule of the lifetime, which the handler checks when it is built and the answer again when one is built by
     * hand: one rule, written here alone.
     *
     * @throws InvalidArgumentException when the lifetime is not a number of seconds
     */
    public static function assertCacheLifetime(int $maxAge): void
    {
        if ($maxAge < 0) {
            throw new InvalidArgumentException('The cache lifetime of the metadata is a number of seconds (spec/saml.md section 6.1 step 6).');
        }
    }

    /**
     * The rule of S-12, which the handler checks when it is built and the configuration of the bundle when it is read:
     * a service provider that honours the cacheDuration fetches the metadata again, and the next certificate with it,
     * before the staged key signs, which a cacheDuration as long as the staging window would not leave it time for.
     *
     * @param int $cacheDuration how long a service provider may keep the metadata, in seconds
     * @param int $stagingDelay how long a staged SAML key is published before it signs, in seconds
     *
     * @throws InvalidArgumentException when the cacheDuration is under one second, or not shorter than the staging delay
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
