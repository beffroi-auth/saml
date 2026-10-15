<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\ServiceProvider;

use Beffroi\Saml\Domain\Metadata\Certificate;
use DateTimeImmutable;

/**
 * What a reading of the metadata of a service provider returns (spec/saml.md section 5.2): the entity ID of the
 * document, its `validUntil`, null when it carries none, the certificates of its service provider role a key for
 * encryption is in, a `KeyDescriptor` whose `use` is `encryption` or absent (S-7), and whether that role says it signs
 * its authentication requests, its `AuthnRequestsSigned`, false when absent (Metadata §2.4.4, S-9).
 */
final readonly class ServiceProviderMetadata
{
    /**
     * @param list<Certificate> $encryptionCertificates
     */
    public function __construct(
        public string $entityId,
        public ?DateTimeImmutable $validUntil,
        public array $encryptionCertificates,
        public bool $authnRequestsSigned = false,
    ) {
    }
}
