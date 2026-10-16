<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Port\KeptSigningKeyProviderInterface;
use Beffroi\Saml\Application\Metadata\SigningCertificates;
use Beffroi\Saml\Bridge\Pki\RsaPrivateKey;
use Beffroi\Saml\Domain\Key\SamlSigningAlgorithmInterface;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Dsig\Exception\InvalidKey;
use Beffroi\Xml\Dsig\PrivateKey;
use Beffroi\Xml\Dsig\SignatureAlgorithm;

/**
 * The active SAML key of a tenant as Dsig signs with it, under RSA-SHA256 (spec/saml.md S-15, S-27), which every
 * answer of the identity provider is signed by: the core's key, opened by the KMS once per process
 * (KeptSigningKeyProviderInterface), turned into a key of OpenSSL in memory for the call and dropped with it (S-1);
 * and its certificate, the one the metadata publish for that key (SigningCertificates), which every signature carries
 * in its KeyInfo (S-37).
 */
final readonly class TenantSigning
{
    public function __construct(
        private KeptSigningKeyProviderInterface $keys,
        private SamlSigningAlgorithmInterface $algorithm,
        private SigningCertificates $certificates,
    ) {
    }

    /**
     * @throws KeyNotFoundException when the tenant holds no active SAML key
     * @throws KmsUnavailableException when the KMS does not answer to open it
     * @throws InvalidKey when Dsig refuses to sign with it, under 2 048 bits (D-16)
     * @throws InvalidArgumentException when its private half is not the one of its public JWK, or not RSA
     * @throws RuntimeException when its certificate cannot be built, or does not verify
     */
    public function of(Tenant $tenant): Signing
    {
        $key = $this->keys->activeKeptSigningKey($tenant, $this->algorithm);

        return new Signing(
            PrivateKey::fromPem(RsaPrivateKey::pem($key)),
            SignatureAlgorithm::RsaSha256,
            $this->certificates->ofOpened($key)->pem(),
        );
    }
}
