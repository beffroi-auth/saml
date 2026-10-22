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
 * The metadata of the service provider of a tenant (spec/saml.md section 6.9): its entity ID, its own (S-38), the
 * certificate of each SAML key of the tenant in service, the key of both roles (S-40), its assertion consumer service
 * under its issuer, and the cacheDuration an upstream identity provider keeps it for, the one of the metadata of the
 * identity provider, shorter than the staging delay of a SAML key (S-12). That its requests are signed and that it
 * wants its assertions signed is what it is, and no setting (S-39).
 *
 * The metadata for one upstream identity provider are the same document with the certificate of each key that provider
 * encrypts for, the newest first (S-65, section 6.12): published to that provider alone, at a URL that names it, so
 * that no provider reads the certificate of another. Those at the URL of the entity ID carry none.
 */
final readonly class ServiceProviderMetadataHandler
{
    /**
     * @param int $maxAge how long a cache may hold the metadata, in seconds: the max-age of the keys of the tenant
     * @param int $cacheDuration how long an upstream identity provider may keep the metadata, in seconds (S-12)
     * @param int $stagingDelay how long a staged SAML key is published before it signs, in seconds: what the
     *                          cacheDuration is shorter than (S-12)
     *
     * @throws InvalidArgumentException when the lifetime is not a number of seconds, or the cacheDuration is not
     *                                  shorter than the staging delay: a deployment learns it at boot
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
     * @throws KeyNotFoundException when the tenant holds no SAML key in service (section 6.9 step 1)
     * @throws KmsUnavailableException when the KMS does not answer to open a key whose certificate is not built yet
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
     * The metadata given to one upstream identity provider, with the certificate of each key it encrypts for (S-65,
     * section 6.12).
     *
     * @param string $identityProvider the entity ID of that provider
     *
     * @throws KeyNotFoundException when the tenant holds no key of that provider in service, or no SAML signing key
     * @throws KmsUnavailableException when the KMS does not answer to open a key whose certificate is not built yet
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
     * @throws KeyNotFoundException when the tenant holds no SAML key in service (section 6.9 step 1)
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
