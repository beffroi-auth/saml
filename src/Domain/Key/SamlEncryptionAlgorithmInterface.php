<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Key;

use Beffroi\Core\Domain\Key\KeptEncryptionAlgorithmInterface;

/**
 * The algorithm of the key an upstream identity provider encrypts an assertion for (spec/saml.md S-64): a key of the
 * tenant in every way, drawn by the generator, sealed by the KMS, staged, active, retiring and retired on the four
 * steps of every key and rotated by the same commands, and published as a certificate in the metadata of the service
 * provider given to that provider alone (S-65), never in the JWK Set. It extends the core's
 * KeptEncryptionAlgorithmInterface for that reason, a key the tenant keeps and is encrypted to, which the core opens
 * with the KMS once per process when an assertion is decrypted (S-66).
 *
 * One algorithm per provider, named after it: the core keeps one active key per algorithm and rotates each apart from
 * the others, so that the key of one provider is never the key of another, which is the precondition enc.md E-15
 * states of a decryption under the signature of the peer. The name is NAME_PREFIX followed by the entity ID of the
 * provider, as identityProvider() answers it. The family takes the figures of the SAML signing key (S-12), whose
 * constants SamlSigningAlgorithmInterface holds.
 */
interface SamlEncryptionAlgorithmInterface extends KeptEncryptionAlgorithmInterface, CertifiedKeyAlgorithmInterface
{
    /**
     * What the name of every algorithm of the family begins with, the entity ID of the provider after it (S-64).
     */
    public const string NAME_PREFIX = 'SAML-ENCRYPTION:';

    /**
     * The entity ID of the upstream identity provider the key belongs to, compared exactly (M-8).
     */
    public function identityProvider(): string;
}
