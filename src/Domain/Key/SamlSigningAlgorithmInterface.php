<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Key;

use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;

/**
 * The algorithm of the key a tenant signs its SAML messages with (spec/saml.md section 5.1, S-1): a key of the tenant
 * in every way, drawn by the generator, sealed by the KMS, staged, active, retiring and retired on the four steps of
 * every key and rotated by the same commands, and published as a certificate in the metadata of its identity
 * provider (section 6.1), never in its JWK Set. It does not extend the core's PublishedKeyAlgorithmInterface for that
 * reason: a relying party that reads the JWK Set has no use for it, and a key in that set is a key the set entitles
 * its reader to verify a JWS with.
 *
 * It names itself rather than naming a JOSE algorithm, as the keys the tenant keeps do: a tenant holds one active key
 * per algorithm, and a SAML key answering to the name of a JWS algorithm would be one pair doing two jobs. Its key
 * type is RSA, the only key Dsig takes (D-16); which XML signature algorithm it signs under is the message's.
 */
interface SamlSigningAlgorithmInterface extends KeyAlgorithmInterface
{
}
