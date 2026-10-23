<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Key;

use Beffroi\Core\Domain\Key\KeptSigningAlgorithmInterface;

/**
 * The algorithm of the key a tenant signs its SAML messages with (spec/saml.md section 5.1, S-1): a key of the tenant
 * in every way, drawn by the generator, sealed by the KMS, staged, active, retiring and retired on the four steps of
 * every key and rotated by the same commands, and published as a certificate in the metadata of its identity
 * provider (section 6.1), never in its JWK Set. It does not extend the core's PublishedKeyAlgorithmInterface for that
 * reason: a relying party that reads the JWK Set has no use for it, and a key in that set is a key the set entitles
 * its reader to verify a JWS with. It extends the core's KeptSigningAlgorithmInterface instead, a key the tenant keeps
 * and signs with, which the core opens with the KMS once per process when an assertion is signed (section 6.4 step 7).
 *
 * It names itself rather than naming a JOSE algorithm, as the keys the tenant keeps do: a tenant holds one active key
 * per algorithm, and a SAML key answering to the name of a JWS algorithm would be one pair doing two jobs. Its key
 * type is RSA, the only key Dsig takes (D-16); which XML signature algorithm it signs under is the message's.
 *
 * Its keys are a family of their own (S-12, section 7): a service provider reads the metadata once a day at best, and
 * one that holds a certificate an administrator uploaded reads nothing, so a key of this family is published days
 * before it signs and works a year. The two constants are the default figures of the family, which a deployment may
 * set otherwise.
 */
interface SamlSigningAlgorithmInterface extends KeptSigningAlgorithmInterface, CertifiedKeyAlgorithmInterface
{
    /**
     * How long a staged SAML key is published before it signs, in seconds: seven days, seven times the cacheDuration
     * of the metadata and a calendar week for an administrator who uploads certificates (section 7).
     */
    public const int STAGING_DELAY = 604_800;

    /**
     * How long a SAML key works before a successor is staged for it, in seconds: 365 days, every rotation of it being
     * a step for whoever pinned its certificate (section 7).
     */
    public const int AGE = 31_536_000;
}
