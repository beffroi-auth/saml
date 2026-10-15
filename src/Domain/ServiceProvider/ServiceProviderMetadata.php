<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\ServiceProvider;

use Beffroi\Saml\Domain\Metadata\Certificate;
use DateTimeImmutable;

/**
 * What a reading of the metadata of a service provider returns (spec/saml.md section 5.2): the entity ID of the
 * document, its `validUntil`, null when it carries none, the certificates of its service provider role a key for
 * encryption is in, a `KeyDescriptor` whose `use` is `encryption` or absent (S-7), those a key for signing is in, a
 * `KeyDescriptor` whose `use` is `signing` or absent (S-11), and whether that role says it signs its authentication
 * requests, its `AuthnRequestsSigned`, false when absent (Metadata §2.4.4, S-9).
 *
 * No member is defaulted: the two that decide S-9 and S-11 are what a reader that left them out would report as a
 * provider that says nothing and holds no key, silently, so leaving one out fails where it is written.
 */
final readonly class ServiceProviderMetadata
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
