<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Metadata;

interface PeerInterface
{
    public string $entityId { get; }

    public MetadataLocation $metadata { get; }

    /**
     * @var list<Certificate>
     */
    public array $metadataSigners { get; }

    public function readsSigned(): bool;
}
