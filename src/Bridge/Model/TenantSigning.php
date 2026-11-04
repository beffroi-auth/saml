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
 * spec/saml.md S-15, S-27, S-37. The private key is built for each call and never kept (S-1).
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
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
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
