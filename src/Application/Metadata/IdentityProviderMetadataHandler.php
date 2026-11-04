<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Saml\Domain\Key\SamlSigningAlgorithmInterface;
use Beffroi\Saml\Domain\Metadata\IdentityProviderDescription;
use Beffroi\Saml\Domain\Metadata\PublishedMetadata;
use Beffroi\Saml\Port\IdentityProviderEndpointsInterface;
use Beffroi\Saml\Port\MetadataWriterInterface;
use LogicException;
use function sprintf;

/**
 * spec/saml.md section 6.1, S-4, S-12
 */
final readonly class IdentityProviderMetadataHandler
{
    /**
     * The max-age of the JWK Set, in seconds, which the staging window of a key derives from.
     */
    public const int DEFAULT_MAX_AGE = 300;

    /**
     * In seconds, shorter than the staging delay of a SAML key (S-12).
     */
    public const int DEFAULT_CACHE_DURATION = 86_400;

    /**
     * @param int $maxAge in seconds
     * @param int $cacheDuration in seconds
     * @param int $stagingDelay in seconds
     *
     * @throws InvalidArgumentException when the lifetime is not a number of seconds, or the cacheDuration is not
     *                                  shorter than the staging delay
     */
    public function __construct(
        private SigningCertificates $certificates,
        private IdentityProviderEndpointsInterface $endpoints,
        private MetadataWriterInterface $writer,
        private bool $wantAuthnRequestsSigned = true,
        private int $maxAge = self::DEFAULT_MAX_AGE,
        private int $cacheDuration = self::DEFAULT_CACHE_DURATION,
        int $stagingDelay = SamlSigningAlgorithmInterface::STAGING_DELAY,
    ) {
        PublishedMetadata::assertCacheLifetime($maxAge);
        PublishedMetadata::assertCacheDuration($cacheDuration, $stagingDelay);
    }

    /**
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     * @throws LogicException when the routes are not mounted under the issuer of the tenant
     * @throws RuntimeException when a certificate cannot be built
     */
    public function handle(Tenant $tenant): PublishedMetadata
    {
        $certificates = $this->certificates->of($tenant);
        if ($certificates === []) {
            throw new KeyNotFoundException(sprintf(
                'Tenant "%s" holds no SAML signing key: its identity provider has no metadata to publish (spec/saml.md section 6.1 step 1).',
                $tenant->slug,
            ));
        }

        return new PublishedMetadata(
            $this->writer->write(new IdentityProviderDescription(
                $this->endpoints->locate($tenant),
                $certificates,
                $this->wantAuthnRequestsSigned,
                $this->cacheDuration,
            )),
            $this->maxAge,
        );
    }
}
