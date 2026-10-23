<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Port\CanForgetAcceptedMetadataInterface;

/**
 * The accepted document of a peer forgotten, a service provider or an upstream identity provider (spec/saml.md S-6,
 * S-42, section 6.2): S-6 holds a peer to the newest document accepted and nothing in a refresh goes back on it, so a
 * peer that went back to a document without validUntil is refused until an operator forgets the one accepted. The
 * next refresh then registers it as a first one. One per role, built with the repository of its table.
 *
 * Its entity ID is compared exactly, and whether the configuration still declares it does not matter: what is
 * forgotten is a row, the row of a declaration removed among them (section 12).
 */
final readonly class AcceptedMetadataForgetting
{
    public function __construct(
        private AcceptedMetadataRepositoryInterface $accepted,
        private CanForgetAcceptedMetadataInterface $forgetting,
    ) {
    }

    /**
     * @return bool false when no document is accepted for that entity ID, and nothing was removed
     */
    public function forget(Tenant $tenant, string $entityId): bool
    {
        $accepted = $this->accepted->find($tenant, $entityId);
        if (! $accepted instanceof AcceptedMetadata) {
            return false;
        }
        $this->forgetting->forget($accepted);

        return true;
    }
}
