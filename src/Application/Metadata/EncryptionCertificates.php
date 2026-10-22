<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\Metadata;

use function array_map;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Port\KeySealerInterface;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Saml\Domain\Key\UpstreamEncryptionKeys;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Port\CertificateIssuerInterface;

/**
 * The certificate of each key an upstream identity provider encrypts for (spec/saml.md S-65, section 6.12 step 2):
 * staged, active and retiring, the newest first, so that the next one is the one the provider takes from its staging,
 * and those of that provider alone, so that it never reads the certificate of another (S-64).
 *
 * Each built once per process and kept while its key is in service, the private half opened for it dropped at once
 * (S-1, S-3), as SigningCertificates keeps the certificates of the signing keys; those of the other providers of the
 * tenant are kept as long as their keys are in service.
 */
final readonly class EncryptionCertificates
{
    private BuiltCertificates $built;

    public function __construct(
        private TenantKeyRepositoryInterface $keys,
        KeySealerInterface $sealer,
        CertificateIssuerInterface $issuer,
    ) {
        $this->built = new BuiltCertificates($sealer, $issuer);
    }

    /**
     * @throws KmsUnavailableException when the KMS does not answer to open a key whose certificate is not built yet
     * @throws InvalidArgumentException when a key is not the one its public JWK says
     * @throws RuntimeException when a key of the provider shares its modulus with another key in service (S-64), or a
     *                          certificate cannot be built, or does not verify
     *
     * @return list<Certificate> the newest first, none when the tenant holds no key of that provider in service
     */
    public function of(Tenant $tenant, string $identityProvider): array
    {
        $inService = $this->keys->findInService($tenant);
        $this->built->keepInService($tenant, $inService);

        return array_map(
            $this->built->of(...),
            UpstreamEncryptionKeys::of($inService, $identityProvider)->keys,
        );
    }
}
