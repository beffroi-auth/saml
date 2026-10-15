<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\ServiceProvider;

/**
 * The name formats of a SAML attribute (Core §8.2): a closed set the protocol fixes, which an attribute mapping
 * carries and nothing acts on (spec/saml.md section 5.2). `uri` is the default of a declaration, the format the SAML
 * V2.0 interoperability profiles ask for.
 */
enum AttributeNameFormat: string
{
    case Unspecified = 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified';
    case Uri = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri';
    case Basic = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';

    /**
     * The format a declaration names by the last segment of its URI, as the configuration writes it.
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
