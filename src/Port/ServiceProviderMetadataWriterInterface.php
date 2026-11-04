<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Saml\Domain\Metadata\ServiceProviderDescription;

interface ServiceProviderMetadataWriterInterface
{
    public function write(ServiceProviderDescription $description): string;
}
