<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Key;

use Beffroi\Core\Domain\Key\KeptSigningAlgorithmInterface;

/**
 * spec/saml.md section 5.1, S-1. Not a PublishedKeyAlgorithmInterface: a key in the JWK Set is one its reader may
 * verify a JWS with. It names itself rather than a JOSE algorithm, so that one key pair never does two jobs.
 */
interface SamlSigningAlgorithmInterface extends KeptSigningAlgorithmInterface, CertifiedKeyAlgorithmInterface
{
    /**
     * In seconds: seven days, seven times the cacheDuration of the metadata and a calendar week for an administrator
     * who uploads certificates.
     */
    public const int STAGING_DELAY = 604_800;

    /**
     * In seconds: 365 days, every rotation being a step for whoever pinned its certificate.
     */
    public const int AGE = 31_536_000;
}
