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
 * The metadata of a peer registered the first time and refreshed every time after, one procedure for either role
 * (spec/saml.md section 6.2, section 6.10, S-42): read from the location its declaration names, by the channel or
 * under the signers it pins (S-5), held by the role to what it requires of the document, never expired, nor older than
 * the document accepted when it was read under those signers (S-6), and kept as the bytes that were read (S-8). One
 * per role, built with the role and the repository of its table.
 *
 * A refusal leaves the accepted document as it was and is returned rather than thrown, so that a refresh of every
 * peer of the role reads each of them whatever one answers.
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
     * Every peer of the role the tenant declares, in the order of the declaration, each one isolated from the others:
     * an exception that is not a refusal, a store or a reader that fails, is reported for the peer it was thrown for,
     * and the next one is read.
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
     * Section 6.2 steps 2 to 7.
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
