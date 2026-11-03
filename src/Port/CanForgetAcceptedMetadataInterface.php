<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;

/**
 * A companion of AcceptedMetadataRepositoryInterface: the accepted document of a peer removed, for the operator who
 * forgets it (spec/saml.md S-6, section 6.2), the application's, one per role.
 */
interface CanForgetAcceptedMetadataInterface
{
    public function forget(AcceptedMetadata $metadata): void;
}
