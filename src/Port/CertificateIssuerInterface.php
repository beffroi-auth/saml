<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Key\UnsealedKey;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Saml\Domain\Metadata\Certificate;

/**
 * What wraps a SAML key of a tenant in the certificate its metadata publishes (spec/saml.md section 6.1 step 2, S-3):
 * self-signed, around the public half of the key, its bytes a function of the key and of its tenant.
 */
interface CertificateIssuerInterface
{
    /**
     * @param UnsealedKey $key a key whose algorithm is a SamlSigningAlgorithmInterface, opened by the KMS
     *
     * @throws InvalidArgumentException when the key is not a SAML signing key, or its private half is not the one of
     *                                  its public JWK
     * @throws RuntimeException when the certificate cannot be signed, or does not verify under its own public key
     */
    public function selfSigned(UnsealedKey $key): Certificate;
}
