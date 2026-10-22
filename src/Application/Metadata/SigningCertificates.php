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
 * The certificate of each SAML key of a tenant in service (spec/saml.md section 6.1 step 2): staged, active and
 * retiring, in creation order, so that the next one is published before it signs anything (S-2).
 *
 * A certificate is built once per process and kept for as long as its key is in service: what is kept is the
 * certificate, which is public, and never the key, which is opened by the KMS for the one signature the certificate
 * carries and dropped, the active key's as any other, so that serving the metadata leaves no private half open in the
 * process (S-1). The metadata is read by anybody, so the KMS is asked at most once per key and per process for a
 * certificate, never once per request (S-3). A process that signs opens the active key through the core, which keeps
 * it to sign (S-15): the KMS is asked for that key at most twice, once for its certificate when the metadata are served
 * first and once to sign, and once when the process signs first, the certificate then built from the key the signature
 * opened (ofOpened(), S-37). A certificate built again is the same bytes, so two processes publish the same one.
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
     * @throws KmsUnavailableException when the KMS does not answer to open a key whose certificate is not built yet
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
     * The certificate of a SAML key already opened, the active one a signature is made with, whose KeyInfo carries it
     * (S-37): the one of() lists for that key, kept with it, built from the key handed over when it is not built yet,
     * so that the KMS is not asked again.
     *
     * @param UnsealedKey $key a key whose algorithm is a SamlSigningAlgorithmInterface, opened by the KMS
     *
     * @throws InvalidArgumentException when the key is not a SAML signing key, or not the one its public JWK says
     * @throws RuntimeException when the certificate cannot be built, or does not verify
     */
    public function ofOpened(UnsealedKey $key): Certificate
    {
        return $this->built->ofOpened($key);
    }
}
