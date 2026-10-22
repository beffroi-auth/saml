<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Metadata;

use Beffroi\Core\Exception\InvalidArgumentException;
use function sprintf;

/**
 * Where and as whom the service provider of a tenant is reached (spec/saml.md S-38, S-39, section 6.9 step 3): its
 * entity ID, the URL of its metadata unless the deployment names another, the URL of its metadata, and the URL of its
 * assertion consumer service, where a response arrives over HTTP-POST. Located under the issuer of the tenant by
 * whoever holds the routes, never read from a request (S-39), the entity ID a deployment names held by the locator to
 * the rule of the model (ModelEntityId, M-6), which checks each URL again when the metadata is written.
 */
final readonly class ServiceProviderEndpoints
{
    public function __construct(
        public string $entityId,
        public string $metadata,
        public string $assertionConsumerService,
    ) {
    }

    /**
     * The second rule of S-38, which the bundle checks when its container is compiled and the locator of the service
     * provider when it is first used, should either value hold an environment variable: one entity ID is
     * one md:EntityDescriptor (Metadata §2.3.2), so the service provider of a tenant is never named as its identity
     * provider is, compared exactly (M-8).
     *
     * @param string $entityId the entity ID of the service provider of the tenant
     * @param string $identityProvider the entity ID of the identity provider of the tenant, the URL of its metadata
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
