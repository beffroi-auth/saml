<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\ServiceProvider;

/**
 * Core §8.2
 */
enum AttributeNameFormat: string
{
    case Unspecified = 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified';
    case Uri = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri';
    case Basic = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';

    /**
     * By the last segment of its URI, as the configuration writes it.
     */
    public static function named(string $name): ?self
    {
        foreach (self::cases() as $format) {
            if ($format->value === 'urn:oasis:names:tc:SAML:2.0:attrname-format:' . $name) {
                return $format;
            }
        }

        return null;
    }
}
