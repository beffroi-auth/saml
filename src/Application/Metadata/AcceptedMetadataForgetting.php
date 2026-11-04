<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Port\CanForgetAcceptedMetadataInterface;

/**
 * spec/saml.md S-6, S-42, section 6.2
 */
final readonly class AcceptedMetadataForgetting
{
    public function __construct(
        private AcceptedMetadataRepositoryInterface $accepted,
        private CanForgetAcceptedMetadataInterface $forgetting,
    ) {
    }

    /**
     * @return bool false when no document was accepted for that entity ID
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
