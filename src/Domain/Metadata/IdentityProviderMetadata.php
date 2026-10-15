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
}
