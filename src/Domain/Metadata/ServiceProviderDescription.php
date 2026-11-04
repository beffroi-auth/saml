<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Metadata;

use Beffroi\Core\Exception\InvalidArgumentException;

final readonly class ServiceProviderDescription
{
    /**
     * @param list<Certificate> $signingCertificates
     * @param list<Certificate> $encryptionCertificates those of one upstream identity provider, none otherwise (S-65)
     *
     * @throws InvalidArgumentException when there is no signing certificate
     */
    public function __construct(
        public ServiceProviderEndpoints $endpoints,
        public array $signingCertificates,
        public int $cacheDuration,
        public array $encryptionCertificates = [],
    ) {
        if ($signingCertificates === []) {
            throw new InvalidArgumentException('The metadata of a service provider carries the certificate of a key at least (spec/saml.md section 6.9 step 1).');
        }
    }

    public function entityId(): string
    {
        return $this->endpoints->entityId;
    }
}
