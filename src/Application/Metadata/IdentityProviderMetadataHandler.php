<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Saml\Domain\Metadata\IdentityProviderDescription;
use Beffroi\Saml\Domain\Metadata\IdentityProviderMetadata;
use Beffroi\Saml\Port\IdentityProviderEndpointsInterface;
use Beffroi\Saml\Port\MetadataWriterInterface;
use LogicException;
use function sprintf;

/**
 * The metadata of the identity provider of a tenant (spec/saml.md section 6.1): the certificate of each of its SAML
 * keys in service, its endpoints under its issuer, and whether it wants the requests it receives signed, which is the
 * setting of the tenant and true unless it says otherwise (S-4, model.md section 6.9).
 */
final readonly class IdentityProviderMetadataHandler
{
    /**
     * The max-age of the JWK Set, which the staging window of a key derives from (architecture §3.3).
     */
    public const int DEFAULT_MAX_AGE = 300;

    /**
     * @param bool $wantAuthnRequestsSigned the setting of the tenant (S-4)
     * @param int $maxAge how long a cache may hold the metadata, in seconds: the max-age of the keys of the tenant
     *
     * @throws InvalidArgumentException when the lifetime is not a number of seconds: a deployment learns it at boot
     */
    public function __construct(
        private SigningCertificates $certificates,
        private IdentityProviderEndpointsInterface $endpoints,
        private MetadataWriterInterface $writer,
        private bool $wantAuthnRequestsSigned = true,
        private int $maxAge = self::DEFAULT_MAX_AGE,
    ) {
        IdentityProviderMetadata::assertCacheLifetime($maxAge);
    }

    /**
     * @throws KeyNotFoundException when the tenant holds no SAML key in service (section 6.1 step 1)
     * @throws KmsUnavailableException when the KMS does not answer to open a key whose certificate is not built yet
     * @throws LogicException when the routes are not mounted under the issuer of the tenant
     * @throws RuntimeException when a certificate cannot be built
     */
    public function handle(Tenant $tenant): IdentityProviderMetadata
    {
        $certificates = $this->certificates->of($tenant);
        if ($certificates === []) {
            throw new KeyNotFoundException(sprintf(
                'Tenant "%s" holds no SAML signing key: its identity provider has no metadata to publish (spec/saml.md section 6.1 step 1).',
                $tenant->slug,
            ));
        }

        return new IdentityProviderMetadata(
            $this->writer->write(new IdentityProviderDescription(
                $this->endpoints->locate($tenant),
                $certificates,
                $this->wantAuthnRequestsSigned,
            )),
            $this->maxAge,
        );
    }
}
