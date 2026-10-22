<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;

/**
 * Where the newest accepted metadata document of each peer of one role of a tenant is kept (spec/saml.md S-6, S-8,
 * S-42): the bundle's, which seals the document, one per role, each the table of its role and the rows of that role
 * only.
 */
interface AcceptedMetadataRepositoryInterface
{
    public function find(Tenant $tenant, string $entityId): ?AcceptedMetadata;

    /**
     * The first document accepted for a peer of a tenant (section 6.2 step 7): written unless another process
     * registered that peer since it was found to have none, its row then kept and nothing written.
     *
     * @return bool false when another process registered the peer first
     */
    public function register(AcceptedMetadata $metadata): bool;

    /**
     * The accepted document of a peer, which a newer one replaced (section 6.2 step 7).
     */
    public function save(AcceptedMetadata $metadata): void;
}
