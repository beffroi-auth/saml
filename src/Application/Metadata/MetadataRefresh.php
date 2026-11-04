<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;
use Beffroi\Saml\Domain\Metadata\PeerInterface;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Port\MetadataFetcherInterface;
use Exception;
use Psr\Clock\ClockInterface;

/**
 * spec/saml.md section 6.2, section 6.10, S-5, S-6, S-8, S-42
 *
 * @template TPeer of PeerInterface
 */
final readonly class MetadataRefresh
{
    /**
     * @param PeerRoleInterface<TPeer> $role
     */
    public function __construct(
        private PeerRoleInterface $role,
        private MetadataFetcherInterface $fetcher,
        private AcceptedMetadataRepositoryInterface $accepted,
        private ClockInterface $clock,
    ) {
    }

    /**
     * Each peer isolated from the others: what one throws is reported for it, and the next one is read.
     *
     * @return list<MetadataRefreshment>
     */
    public function refreshAll(Tenant $tenant): array
    {
        $refreshments = [];
        foreach ($this->role->of($tenant) as $peer) {
            try {
                $refreshments[] = $this->refresh($tenant, $peer);
            } catch (Exception $failure) {
                $refreshments[] = MetadataRefreshment::failed($this->role->noun(), $peer->entityId, $failure);
            }
        }

        return $refreshments;
    }

    /**
     * @param TPeer $peer
     */
    public function refresh(Tenant $tenant, PeerInterface $peer): MetadataRefreshment
    {
        try {
            return $this->accept($tenant, $peer);
        } catch (MetadataRefusedException $exception) {
            return MetadataRefreshment::refused($this->role->noun(), $peer->entityId, $exception->getMessage());
        }
    }

    /**
     * Section 6.2 steps 2 to 7
     *
     * @param TPeer $peer
     *
     * @throws MetadataRefusedException
     */
    private function accept(Tenant $tenant, PeerInterface $peer): MetadataRefreshment
    {
        $noun = $this->role->noun();
        $document = $this->fetcher->fetch($peer->metadata);
        $metadata = $this->role->read($peer, $document);
        $accepted = $this->accepted->find($tenant, $peer->entityId);
        if (! $accepted instanceof AcceptedMetadata) {
            return $this->accepted->register($this->role->accepted($tenant, $metadata, $document, $this->clock->now()))
                ? MetadataRefreshment::registered($noun, $peer->entityId)
                : MetadataRefreshment::registeredMeanwhile($noun, $peer->entityId);
        }
        if ($accepted->holds($document)) {
            return MetadataRefreshment::unchanged($noun, $peer->entityId);
        }
        $accepted->replaceWith($metadata, $document, $this->clock->now());
        $this->accepted->save($accepted);

        return MetadataRefreshment::refreshed($noun, $peer->entityId);
    }
}
