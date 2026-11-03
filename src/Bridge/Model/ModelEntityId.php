<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Uri;

/**
 * An entity ID the deployment names held to the rule of saml2-model's Uri, the one its MetadataWriter writes an entity
 * ID under and its MetadataReader reads one under (spec/saml.md S-38, S-42, M-6): absolute, at most 1024 characters,
 * no whitespace, no control character and no format or invisible character. One rule, read where the model reads it,
 * so that what the configuration accepts is what the metadata can carry: the entity ID of the service provider of the
 * tenant, which the application checks when its container is compiled and its locator at the first use of one an
 * environment variable kept from the compilation, and the entity ID an upstream identity provider is declared under,
 * which ConfigurationUpstreamIdentityProviders checks when it builds the declaration, at the compilation too.
 */
final readonly class ModelEntityId
{
    /**
     * The entity ID of the service provider of the tenant (S-38).
     *
     * @throws InvalidArgumentException when the entity ID is no URI of M-6, naming the rule and never the value (M-16)
     */
    public static function read(string $entityId): string
    {
        return self::readAs($entityId, 'The entity ID of the service provider of a tenant is refused (spec/saml.md S-38): ');
    }

    /**
     * The entity ID an upstream identity provider is declared under (S-42), which the entity ID of its metadata is
     * compared to exactly.
     *
     * @throws InvalidArgumentException when the entity ID is no URI of M-6, naming the rule and never the value (M-16)
     */
    public static function ofIdentityProvider(string $entityId): string
    {
        return self::readAs($entityId, 'The entity ID of an identity provider is refused (spec/saml.md S-42): ');
    }

    /**
     * @throws InvalidArgumentException
     */
    private static function readAs(string $entityId, string $refused): string
    {
        try {
            return Uri::read($entityId);
        } catch (MalformedMessage $refusal) {
            throw new InvalidArgumentException($refused . $refusal->getMessage(), 0, $refusal);
        }
    }
}
