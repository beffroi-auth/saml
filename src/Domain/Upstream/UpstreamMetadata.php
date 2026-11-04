<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Upstream;

use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\Metadata\PeerMetadataInterface;
use DateTimeImmutable;

final readonly class UpstreamMetadata implements PeerMetadataInterface
{
    /**
     * @param list<Certificate> $signingCertificates
     */
    public function __construct(
        public string $entityId,
        public ?DateTimeImmutable $validUntil,
        public array $signingCertificates,
        public bool $readSigned,
    ) {
    }
}
