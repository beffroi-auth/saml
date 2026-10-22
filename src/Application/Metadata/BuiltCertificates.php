<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\Metadata;

use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Key\UnsealedKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Port\KeySealerInterface;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Port\CertificateIssuerInterface;
use function str_starts_with;

/**
 * The certificates a process built for the SAML keys of its tenants and keeps (spec/saml.md S-3, S-65): one per key,
 * built once and kept for as long as the key is in service, ranged by tenant and "kid". What is kept is the
 * certificate, which is public, and never the key, which is opened by the KMS for the one signature the certificate
 * carries and dropped (S-1): the KMS is asked at most once per key and per process for a certificate. A certificate
 * built again is the same bytes, so that two processes publish the same one.
 *
 * The way SigningCertificates keeps the certificates of the signing keys, and EncryptionCertificates those of the keys
 * the upstream identity providers encrypt for, written once.
 */
final class BuiltCertificates
{
    /**
     * @var array<string, Certificate> by tenant and kid
     */
    private array $built = [];

    public function __construct(
        private readonly KeySealerInterface $sealer,
        private readonly CertificateIssuerInterface $issuer,
    ) {
    }

    /**
     * The certificate of a key, the one this process built, or built from the key opened by the KMS and dropped.
     *
     * @throws KmsUnavailableException when the KMS does not answer to open a key whose certificate is not built yet
     * @throws InvalidArgumentException when the key is not one the issuer certifies, or not the one its public JWK says
     * @throws RuntimeException when the certificate cannot be built, or does not verify
     */
    public function of(TenantKey $key): Certificate
    {
        return $this->built[self::index($key->tenant, $key->kid)] ??= $this->issuer->selfSigned(new UnsealedKey(
            $key,
            $this->sealer->unseal($key->tenant, $key->sealedPrivateJwk),
        ));
    }

    /**
     * The certificate of a key already opened, built from it when it is not built yet, so that the KMS is not asked
     * again (S-37).
     *
     * @throws InvalidArgumentException when the key is not one the issuer certifies, or not the one its public JWK says
     * @throws RuntimeException when the certificate cannot be built, or does not verify
     */
    public function ofOpened(UnsealedKey $key): Certificate
    {
        return $this->built[self::index($key->key->tenant, $key->key->kid)] ??= $this->issuer->selfSigned($key);
    }

    /**
     * The certificates of the keys of that tenant that are not in service forgotten: a key that has left the service
     * has nothing more to publish.
     *
     * @param list<TenantKey> $inService the keys of the tenant in service
     */
    public function keepInService(Tenant $tenant, array $inService): void
    {
        $kept = [];
        foreach ($inService as $key) {
            $kept[self::index($tenant, $key->kid)] = true;
        }
        $prefix = self::index($tenant, '');
        foreach ($this->built as $index => $certificate) {
            if (! isset($kept[$index]) && str_starts_with($index, $prefix)) {
                unset($this->built[$index]);
            }
        }
    }

    private static function index(Tenant $tenant, string $kid): string
    {
        return $tenant->id->toRfc4122() . '/' . $kid;
    }
}
