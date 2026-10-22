<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Metadata;

use Beffroi\Core\Exception\InvalidArgumentException;

/**
 * What the metadata of the service provider of a tenant says (spec/saml.md S-39, section 6.9): where it is reached and
 * as whom, the certificate of each SAML key of the tenant in service, in creation order (S-2, S-40), and how long an
 * upstream identity provider may keep it, in seconds (S-12). That its requests are signed and that it wants the
 * assertions it receives signed is not a setting (S-39), so nothing here carries it.
 *
 * The metadata of the service provider for one upstream identity provider say the same, and the certificate of each
 * key that provider encrypts for, the newest first (S-65, section 6.12); those at the URL of the entity ID carry none.
 */
final readonly class ServiceProviderDescription
{
    /**
     * @param list<Certificate> $signingCertificates
     * @param list<Certificate> $encryptionCertificates those of one upstream identity provider, none otherwise (S-65)
     *
     * @throws InvalidArgumentException when there is no certificate: metadata announcing signed requests with no key
     *                                  to verify them by is not metadata to publish (section 6.9 step 1)
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
