<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Key;

use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;

/**
 * A SAML key algorithm whose certificate the metadata publish (spec/saml.md S-3, S-65).
 */
interface CertifiedKeyAlgorithmInterface extends KeyAlgorithmInterface
{
}
