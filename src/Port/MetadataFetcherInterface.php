<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Saml\Domain\Metadata\MetadataLocation;
use Beffroi\Saml\Exception\MetadataRefusedException;

/**
 * The bytes of the metadata of a peer at the location its declaration names, a service provider's or an upstream
 * identity provider's (spec/saml.md section 6.2 step 2, section 6.10 step 2): the application's, which holds the HTTP
 * client and the file system.
 */
interface MetadataFetcherInterface
{
    /**
     * The maxBytes of Core's Limits, which loads the document: a read stops there (section 7). Deptrac keeps a port off
     * the classes of xml-security, so the number is written here and held equal to Core's by the suite of the package
     * (MetadataFetcherInterfaceTest).
     */
    public const int MAX_BYTES = 1_048_576;

    /**
     * @throws MetadataRefusedException when the location cannot be read, redirects, answers other than 2xx, or holds
     *                                  more than MAX_BYTES
     */
    public function fetch(MetadataLocation $location): string;
}
