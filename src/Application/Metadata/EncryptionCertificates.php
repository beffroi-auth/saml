<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\Metadata;

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
 * spec/saml.md S-64, S-65, S-66, section 6.12 step 2
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
     * @throws KmsUnavailableException
     * @throws InvalidArgumentException when a key is not the one its public JWK says
     * @throws RuntimeException when a key of the provider shares its modulus with another key in service (S-64), or a
     *                          certificate cannot be built, or does not verify
     *
     * @return list<Certificate> the newest first
     */
    public function of(Tenant $tenant, string $identityProvider): array
    {
        $inService = $this->keys->findInService($tenant);
        $this->built->keepInService($tenant, $inService);

        $certificates = [];
        foreach (UpstreamEncryptionKeys::of($inService, $identityProvider)->keys as $key) {
            // A retiring key is no longer announced, though it still opens what was encrypted for it (S-65).
            if ($key->isStaged() || $key->isActive()) {
                $certificates[] = $this->built->of($key);
            }
        }

        return $certificates;
    }
}
