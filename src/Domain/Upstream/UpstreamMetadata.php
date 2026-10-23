<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Upstream;

use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\Metadata\PeerMetadataInterface;
use DateTimeImmutable;

/**
 * What a reading of the metadata of an upstream identity provider returns (spec/saml.md section 5.7): the entity ID of
 * the document, its `validUntil`, null when it carries none, the certificates of its identity provider role a key for
 * signing is in, a `KeyDescriptor` whose `use` is `signing` or absent, one at least (S-43), and whether this reading
 * verified the document under the certificates the declaration pins (S-6). No member is defaulted.
 */
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
