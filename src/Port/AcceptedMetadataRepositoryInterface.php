<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedMetadata;

/**
 * Where the newest accepted metadata document of each service provider of a tenant is kept (spec/saml.md S-6, S-8):
 * the bundle's, which seals the document.
 */
interface AcceptedMetadataRepositoryInterface
{
    public function find(Tenant $tenant, string $entityId): ?AcceptedMetadata;

    public function save(AcceptedMetadata $metadata): void;
}
