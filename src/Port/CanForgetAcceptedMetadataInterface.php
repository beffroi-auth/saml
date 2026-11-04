<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;

interface CanForgetAcceptedMetadataInterface
{
    public function forget(AcceptedMetadata $metadata): void;
}
