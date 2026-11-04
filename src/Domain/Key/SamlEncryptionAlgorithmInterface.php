<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Key;

use Beffroi\Core\Domain\Key\KeptEncryptionAlgorithmInterface;

/**
 * spec/saml.md S-64. One algorithm per upstream identity provider, so that the key of one provider is never the key of
 * another (enc.md E-15).
 */
interface SamlEncryptionAlgorithmInterface extends KeptEncryptionAlgorithmInterface, CertifiedKeyAlgorithmInterface
{
    /**
     * Followed by the entity ID of the provider (S-64).
     */
    public const string NAME_PREFIX = 'SAML-ENCRYPTION:';

    public function identityProvider(): string;
}
