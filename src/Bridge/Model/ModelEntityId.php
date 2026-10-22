<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Uri;

/**
 * The entity ID a deployment names for the service provider of its tenant held to the rule of saml2-model's Uri, the
 * one its MetadataWriter writes an entity ID under (spec/saml.md S-38, M-6): absolute, at most 1024 characters, no
 * whitespace, no control character and no format or invisible character. One rule, read where the model reads it, so
 * that what the configuration accepts is what the metadata can carry: the bundle applies it when its container is
 * compiled, and its locator at the first use of an entity ID an environment variable kept from the compilation.
 */
final readonly class ModelEntityId
{
    /**
     * @throws InvalidArgumentException when the entity ID is no URI of M-6, naming the rule and never the value (M-16)
     */
    public static function read(string $entityId): string
    {
        try {
            return Uri::read($entityId);
        } catch (MalformedMessage $refusal) {
            throw new InvalidArgumentException(
                'The entity ID of the service provider of a tenant is refused (spec/saml.md S-38): ' . $refusal->getMessage(),
                0,
                $refusal,
            );
        }
    }
}
