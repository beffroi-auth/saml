<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;

/**
 * One per role, which seals the document and holds the rows of that role only (spec/saml.md S-6, S-8, S-42).
 */
interface AcceptedMetadataRepositoryInterface
{
    public function find(Tenant $tenant, string $entityId): ?AcceptedMetadata;

    /**
     * @return bool false when another process registered the peer first, its row then kept
     */
    public function register(AcceptedMetadata $metadata): bool;

    public function save(AcceptedMetadata $metadata): void;
}
