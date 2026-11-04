<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Metadata;

use Beffroi\Core\Exception\InvalidArgumentException;
use function sprintf;

final readonly class ServiceProviderEndpoints
{
    public function __construct(
        public string $entityId,
        public string $metadata,
        public string $assertionConsumerService,
    ) {
    }

    /**
     * S-38: one entity ID is one md:EntityDescriptor (Metadata §2.3.2), so the service provider of a tenant is never
     * named as its identity provider is.
     *
     * @throws InvalidArgumentException when the two are one
     */
    public static function assertOwnEntityId(string $entityId, string $identityProvider): void
    {
        if ($entityId === $identityProvider) {
            throw new InvalidArgumentException(sprintf(
                'The entity ID of the service provider of the tenant, "%s", is the one of its identity provider: each role is an entity of its own (spec/saml.md S-38).',
                $entityId,
            ));
        }
    }
}
