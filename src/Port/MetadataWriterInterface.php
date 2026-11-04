<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Saml\Domain\Metadata\IdentityProviderDescription;

interface MetadataWriterInterface
{
    public function write(IdentityProviderDescription $description): string;
}
