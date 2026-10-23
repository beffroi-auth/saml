<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Key;

use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;

/**
 * The algorithm of a SAML key of a tenant whose certificate the metadata publish (spec/saml.md S-3, S-65): the key a
 * tenant signs with, and the key an upstream identity provider encrypts for. What the certificate says the key is for
 * is the use of the key (keyUsage, RFC 5280 §4.2.1.3), so that a kind of SAML key added later is certified by
 * extending this and nothing else.
 */
interface CertifiedKeyAlgorithmInterface extends KeyAlgorithmInterface
{
}
