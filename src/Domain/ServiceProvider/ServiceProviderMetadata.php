<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\ServiceProvider;

use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\Metadata\PeerMetadataInterface;
use DateTimeImmutable;

/**
 * No member is defaulted: a reader that left one out would report, silently, a provider that says nothing and holds no
 * key.
 */
final readonly class ServiceProviderMetadata implements PeerMetadataInterface
{
    /**
     * @param list<Certificate> $encryptionCertificates
     * @param list<Certificate> $signingCertificates
     */
    public function __construct(
        public string $entityId,
        public ?DateTimeImmutable $validUntil,
        public array $encryptionCertificates,
        public bool $authnRequestsSigned,
        public array $signingCertificates,
        public bool $readSigned,
    ) {
    }

    /**
     * S-19: the first in document order, the one a SimpleSAMLphp identity provider takes too.
     */
    public function encryptionCertificate(): ?Certificate
    {
        return $this->encryptionCertificates[0] ?? null;
    }
}
