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
 * spec/saml.md S-1, S-3, S-65
 *
 * Keeps the certificate, which is public, and never the key, dropped once it has signed the certificate.
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
     * @throws KmsUnavailableException
     * @throws InvalidArgumentException when the key is not one the issuer certifies, or not the one its public JWK
     *                                  says
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
     * S-37
     *
     * @throws InvalidArgumentException when the key is not one the issuer certifies, or not the one its public JWK
     *                                  says
     * @throws RuntimeException when the certificate cannot be built, or does not verify
     */
    public function ofOpened(UnsealedKey $key): Certificate
    {
        return $this->built[self::index($key->key->tenant, $key->key->kid)] ??= $this->issuer->selfSigned($key);
    }

    /**
     * @param list<TenantKey> $inService
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
