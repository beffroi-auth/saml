<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\ServiceProvider;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Metadata\Lexical;

/**
 * A claim of the provider sent to a service provider as a SAML attribute (spec/saml.md section 5.2, Core §2.7.3.1):
 * the name of the claim, and the name, the name format and the friendly name of the attribute. The claim name is not
 * checked against the claims the provider holds: what a claim is worth in an assertion is issue #731's.
 */
final readonly class AttributeMapping
{
    /**
     * @throws InvalidArgumentException when a name is not one (section 6.2 step 1)
     */
    public function __construct(
        public string $claim,
        public string $name,
        public AttributeNameFormat $nameFormat = AttributeNameFormat::Uri,
        public ?string $friendlyName = null,
    ) {
        if (! Lexical::isName($claim)) {
            throw new InvalidArgumentException('A claim name is not empty and holds no whitespace (spec/saml.md section 6.2 step 1).');
        }
        if (! Lexical::isName($name)) {
            throw new InvalidArgumentException('An attribute name is not empty, holds no whitespace and is at most 1024 characters (spec/saml.md section 6.2 step 1).');
        }
        if ($nameFormat === AttributeNameFormat::Uri && ! Lexical::isAbsoluteUri($name)) {
            throw new InvalidArgumentException('An attribute name of the uri format is an absolute URI (Core section 8.2.2, spec/saml.md section 6.2 step 1).');
        }
        if ($friendlyName === '') {
            throw new InvalidArgumentException('A friendly name, when given, is not empty (spec/saml.md section 6.2 step 1).');
        }
    }
}
