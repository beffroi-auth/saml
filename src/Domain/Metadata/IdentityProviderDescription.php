<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Metadata;

use Beffroi\Core\Exception\InvalidArgumentException;

final readonly class IdentityProviderDescription
{
    /**
     * @param list<Certificate> $signingCertificates
     *
     * @throws InvalidArgumentException when there is no certificate
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
     * Metadata §4.1
     */
    public function entityId(): string
    {
        return $this->endpoints->metadata;
    }
}
