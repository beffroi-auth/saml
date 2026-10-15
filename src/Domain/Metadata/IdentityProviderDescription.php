<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Metadata;

use Beffroi\Core\Exception\InvalidArgumentException;

/**
 * What the metadata of the identity provider of a tenant says (spec/saml.md section 6.1): where it is reached, the
 * certificate of each of its keys in service, in creation order (S-2), whether it wants the requests it receives
 * signed, the setting of the tenant (S-4), and how long a service provider may keep it, in seconds (S-12).
 */
final readonly class IdentityProviderDescription
{
    /**
     * @param list<Certificate> $signingCertificates
     *
     * @throws InvalidArgumentException when there is no certificate: metadata whose messages nothing verifies is not
     *                                  metadata to publish (section 6.1 step 1)
     */
    public function __construct(
        public IdentityProviderEndpoints $endpoints,
        public array $signingCertificates,
        public bool $wantAuthnRequestsSigned,
        public int $cacheDuration,
    ) {
        if ($signingCertificates === []) {
            throw new InvalidArgumentException('The metadata of an identity provider carries the certificate of a key at least (spec/saml.md section 6.1 step 1).');
        }
    }

    /**
     * The URL of the metadata, the well-known location an entity ID resolves to (Metadata §4.1).
     */
    public function entityId(): string
    {
        return $this->endpoints->metadata;
    }
}
