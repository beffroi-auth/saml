<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Uri;

/**
 * spec/saml.md S-38, S-42, M-6
 *
 * Held to the rule of saml2-model's Uri, so that what the configuration accepts is what the metadata can carry.
 */
final readonly class ModelEntityId
{
    /**
     * S-38
     *
     * @throws InvalidArgumentException when the entity ID is no URI of M-6, naming the rule and never the value (M-16)
     */
    public static function read(string $entityId): string
    {
        return self::readAs($entityId, 'The entity ID of the service provider of a tenant is refused (spec/saml.md S-38): ');
    }

    /**
     * S-42
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
