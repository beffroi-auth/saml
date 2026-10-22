<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Saml\Domain\Metadata\ServiceProviderDescription;

/**
 * What writes the metadata of the service provider of a tenant (spec/saml.md section 6.9 step 4): one
 * md:EntityDescriptor, serialized.
 */
interface ServiceProviderMetadataWriterInterface
{
    public function write(ServiceProviderDescription $description): string;
}
