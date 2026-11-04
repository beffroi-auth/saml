<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Saml\Domain\ServiceProvider\ServiceProviderMetadata;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;

final readonly class ReadServiceProvider
{
    public function __construct(
        public ServiceProviderMetadata $metadata,
        public ServiceProvider $role,
    ) {
    }
}
