<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Saml\Domain\ServiceProvider\MetadataLocation;
use Beffroi\Saml\Exception\MetadataRefusedException;

/**
 * The bytes of the metadata of a service provider at the location its declaration names (spec/saml.md section 6.2
 * step 2): the bundle's, which holds the HTTP client and the file system.
 */
interface MetadataFetcherInterface
{
    /**
     * The maxBytes of Core's Limits, which loads the document: a read stops there (section 7).
     */
    public const int MAX_BYTES = 1_048_576;

    /**
     * @throws MetadataRefusedException when the location cannot be read, redirects, answers other than 2xx, or holds
     *                                  more than MAX_BYTES
     */
    public function fetch(MetadataLocation $location): string;
}
