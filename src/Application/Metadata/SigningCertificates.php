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
use function str_starts_with;

/**
 * The certificate of each SAML key of a tenant in service (spec/saml.md section 6.1 step 2): staged, active and
 * retiring, in creation order, so that the next one is published before it signs anything (S-2).
 *
 * A certificate is built once per process and kept for as long as its key is in service: what is kept is the
 * certificate, which is public, and never the key, which is opened by the KMS for the one signature the certificate
 * carries and dropped, the active key's as any other, so that serving the metadata leaves no private half open in the
 * process (S-1). The metadata is read by anybody, so the KMS is asked once per key and per process for a certificate,
 * never once per request (S-3); a process that signs opens the active key once more, through the core, which keeps it
 * to sign (S-15). A certificate built again is the same bytes, so two processes publish the same one.
 */
final class SigningCertificates
{
    /**
     * @var array<string, Certificate> by tenant and kid
     */
    private array $built = [];

    public function __construct(
        private readonly TenantKeyRepositoryInterface $keys,
        private readonly KeySealerInterface $sealer,
        private readonly CertificateIssuerInterface $issuer,
    ) {
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
        $certificates = [];
        $inService = [];
        foreach ($this->keys->findInService($tenant) as $key) {
            if (! $key->algorithm instanceof SamlSigningAlgorithmInterface) {
                continue;
            }
            $index = self::index($tenant, $key->kid);
            $inService[$index] = true;
            $certificates[] =
                $this->built[$index] ??= $this->issuer->selfSigned(new UnsealedKey(
                    $key,
                    $this->sealer->unseal($tenant, $key->sealedPrivateJwk),
                ));
        }
        $prefix = self::index($tenant, '');
        foreach ($this->built as $index => $certificate) {
            if (! isset($inService[$index]) && str_starts_with($index, $prefix)) {
                unset($this->built[$index]);
            }
        }

        return $certificates;
    }

    private static function index(Tenant $tenant, string $kid): string
    {
        return $tenant->id->toRfc4122() . '/' . $kid;
    }
}
