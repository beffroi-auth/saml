<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Port\KeptSigningKeyProviderInterface;
use Beffroi\Saml\Bridge\Pki\RsaPrivateKey;
use Beffroi\Saml\Domain\Key\SamlSigningAlgorithmInterface;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Dsig\PrivateKey;
use Beffroi\Xml\Dsig\SignatureAlgorithm;

/**
 * The active SAML key of a tenant as Dsig signs with it, under RSA-SHA256 (spec/saml.md S-15, S-27), which every
 * answer of the identity provider is signed by: the core's key, opened by the KMS once per process
 * (KeptSigningKeyProviderInterface), turned into a key of OpenSSL in memory for the call and dropped with it (S-1).
 */
final readonly class TenantSigning
{
    public function __construct(
        private KeptSigningKeyProviderInterface $keys,
        private SamlSigningAlgorithmInterface $algorithm,
    ) {
    }

    /**
     * @throws KeyNotFoundException when the tenant holds no active SAML key
     * @throws KmsUnavailableException when the KMS does not answer to open it
     */
    public function of(Tenant $tenant): Signing
    {
        return new Signing(
            PrivateKey::fromPem(RsaPrivateKey::pem($this->keys->activeKeptSigningKey($tenant, $this->algorithm))),
            SignatureAlgorithm::RsaSha256,
        );
    }
}
