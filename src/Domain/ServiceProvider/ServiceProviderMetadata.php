<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\ServiceProvider;

use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\Metadata\PeerMetadataInterface;
use DateTimeImmutable;

/**
 * What a reading of the metadata of a service provider returns (spec/saml.md section 5.2): the entity ID of the
 * document, its `validUntil`, null when it carries none, the certificates of its service provider role a key for
 * encryption is in, a `KeyDescriptor` whose `use` is `encryption` or absent (S-7), those a key for signing is in, a
 * `KeyDescriptor` whose `use` is `signing` or absent (S-11), whether that role says it signs its authentication
 * requests, its `AuthnRequestsSigned`, false when absent (Metadata §2.4.4, S-9), and whether this reading verified the
 * document under the certificates the declaration pins, `readSigned()`, rather than trusting the channel it came
 * through, `readTrusted()` and the reading back of the accepted document (S-5): what the rule against a rollback holds
 * to the document accepted (S-6).
 *
 * No member is defaulted: the two that decide S-9 and S-11 are what a reader that left them out would report as a
 * provider that says nothing and holds no key, silently, and the one that decides S-6 is said by the reading that knows
 * it, never by whoever replaces the document accepted, so leaving one out fails where it is written.
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
     * The key an assertion is encrypted for (S-19): the first certificate for encryption, in document order, the one
     * a SimpleSAMLphp identity provider takes too; null when the document holds none.
     */
    public function encryptionCertificate(): ?Certificate
    {
        return $this->encryptionCertificates[0] ?? null;
    }
}
