<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Saml\Domain\Key\SamlSigningAlgorithmInterface;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\Metadata\PublishedMetadata;
use Beffroi\Saml\Domain\Metadata\ServiceProviderDescription;
use Beffroi\Saml\Port\ServiceProviderEndpointsInterface;
use Beffroi\Saml\Port\ServiceProviderMetadataWriterInterface;
use LogicException;
use function sprintf;

/**
 * spec/saml.md section 6.9, section 6.12, S-12, S-38, S-39, S-40, S-65
 */
final readonly class ServiceProviderMetadataHandler
{
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
        private EncryptionCertificates $encryptionCertificates,
        private ServiceProviderEndpointsInterface $endpoints,
        private ServiceProviderMetadataWriterInterface $writer,
        private int $maxAge = IdentityProviderMetadataHandler::DEFAULT_MAX_AGE,
        private int $cacheDuration = IdentityProviderMetadataHandler::DEFAULT_CACHE_DURATION,
        int $stagingDelay = SamlSigningAlgorithmInterface::STAGING_DELAY,
    ) {
        PublishedMetadata::assertCacheLifetime($maxAge);
        PublishedMetadata::assertCacheDuration($cacheDuration, $stagingDelay);
    }

    /**
     * The metadata at the URL of the entity ID, which carry no key for encryption (S-39).
     *
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     * @throws LogicException when the routes are not mounted under the issuer of the tenant
     * @throws InvalidArgumentException when the entity ID the deployment names is not one, or is the one of the
     *                                  identity provider of the tenant (S-38)
     * @throws RuntimeException when a certificate cannot be built
     */
    public function handle(Tenant $tenant): PublishedMetadata
    {
        return $this->publish($tenant, []);
    }

    /**
     * S-65, section 6.12
     *
     * @param string $identityProvider the entity ID of that provider
     *
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     * @throws LogicException when the routes are not mounted under the issuer of the tenant
     * @throws InvalidArgumentException when the entity ID the deployment names is not one, or is the one of the
     *                                  identity provider of the tenant (S-38)
     * @throws RuntimeException when a key of that provider shares its modulus with another key in service (S-64), or a
     *                          certificate cannot be built
     */
    public function handleFor(Tenant $tenant, string $identityProvider): PublishedMetadata
    {
        $encryptionCertificates = $this->encryptionCertificates->of($tenant, $identityProvider);
        if ($encryptionCertificates === []) {
            throw new KeyNotFoundException(sprintf(
                'Tenant "%s" holds no key the identity provider "%s" encrypts for: its service provider has no metadata to give it (spec/saml.md section 6.12 step 1).',
                $tenant->slug,
                $identityProvider,
            ));
        }

        return $this->publish($tenant, $encryptionCertificates);
    }

    /**
     * @param list<Certificate> $encryptionCertificates
     *
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     * @throws LogicException
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    private function publish(Tenant $tenant, array $encryptionCertificates): PublishedMetadata
    {
        $certificates = $this->certificates->of($tenant);
        if ($certificates === []) {
            throw new KeyNotFoundException(sprintf(
                'Tenant "%s" holds no SAML signing key: its service provider has no metadata to publish (spec/saml.md section 6.9 step 1).',
                $tenant->slug,
            ));
        }

        return new PublishedMetadata(
            $this->writer->write(new ServiceProviderDescription(
                $this->endpoints->locate($tenant),
                $certificates,
                $this->cacheDuration,
                $encryptionCertificates,
            )),
            $this->maxAge,
        );
    }
}
