<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Saml\Domain\Metadata\IdentityProviderDescription;

/**
 * What writes the metadata of the identity provider of a tenant (spec/saml.md section 6.1 step 5): one
 * md:EntityDescriptor, serialized.
 */
interface MetadataWriterInterface
{
    public function write(IdentityProviderDescription $description): string;
}
