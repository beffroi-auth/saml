<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProviderMetadata;
use Beffroi\Saml\Exception\MetadataRefusedException;

interface ServiceProviderMetadataReaderInterface
{
    /**
     * A document its channel vouches for; what it returns says it was not read signed (S-6).
     *
     * @throws MetadataRefusedException
     */
    public function readTrusted(string $document): ServiceProviderMetadata;

    /**
     * What it returns says it was read signed (S-6).
     *
     * @param list<Certificate> $signers
     *
     * @throws MetadataRefusedException as readTrusted(), and for a document unsigned, signed under another key or
     *                                  without validUntil
     */
    public function readSigned(string $document, array $signers): ServiceProviderMetadata;
}
