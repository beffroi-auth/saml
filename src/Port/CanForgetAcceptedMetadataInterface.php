<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Saml\Domain\ServiceProvider\AcceptedMetadata;

/**
 * A companion of AcceptedMetadataRepositoryInterface: the accepted document of a service provider removed, for the
 * operator who forgets it (spec/saml.md S-6, section 6.2), the bundle's.
 */
interface CanForgetAcceptedMetadataInterface
{
    public function forget(AcceptedMetadata $metadata): void;
}
