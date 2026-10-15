<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Saml\Domain\ServiceProvider\ServiceProviderMetadata;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;

/**
 * One reading of the accepted document of a service provider (spec/saml.md section 6.3 step 1): what this package
 * reads of it, and the model's role, both from that one reading.
 */
final readonly class ReadServiceProvider
{
    public function __construct(
        public ServiceProviderMetadata $metadata,
        public ServiceProvider $role,
    ) {
    }
}
