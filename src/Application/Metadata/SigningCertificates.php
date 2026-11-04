<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\Metadata;

use Beffroi\Core\Domain\Key\UnsealedKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Port\KeySealerInterface;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Saml\Domain\Key\SamlSigningAlgorithmInterface;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Port\CertificateIssuerInterface;

/**
 * spec/saml.md section 6.1 step 2, S-1, S-2, S-3
 */
final readonly class SigningCertificates
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
     * @throws RuntimeException when a certificate cannot be built, or does not verify
     *
     * @return list<Certificate> in the creation order of the keys
     */
    public function of(Tenant $tenant): array
    {
        $inService = $this->keys->findInService($tenant);
        $this->built->keepInService($tenant, $inService);
        $certificates = [];
        foreach ($inService as $key) {
            if ($key->algorithm instanceof SamlSigningAlgorithmInterface) {
                $certificates[] = $this->built->of($key);
            }
        }

        return $certificates;
    }

    /**
     * S-37
     *
     * @throws InvalidArgumentException when the key is not a SAML signing key, or not the one its public JWK says
     * @throws RuntimeException when the certificate cannot be built, or does not verify
     */
    public function ofOpened(UnsealedKey $key): Certificate
    {
        return $this->built->ofOpened($key);
    }
}
