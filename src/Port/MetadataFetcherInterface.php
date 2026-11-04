<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Saml\Domain\Metadata\MetadataLocation;
use Beffroi\Saml\Exception\MetadataRefusedException;

interface MetadataFetcherInterface
{
    /**
     * The maxBytes of Core's Limits, written here because Deptrac keeps a port off xml-security;
     * MetadataFetcherInterfaceTest holds the two equal.
     */
    public const int MAX_BYTES = 1_048_576;

    /**
     * @throws MetadataRefusedException when the location cannot be read, redirects, answers other than 2xx, or holds
     *                                  more than MAX_BYTES
     */
    public function fetch(MetadataLocation $location): string;
}
