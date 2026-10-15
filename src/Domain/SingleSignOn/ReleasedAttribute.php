<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleSignOn;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\ServiceProvider\AttributeNameFormat;

/**
 * One attribute an assertion carries (spec/saml.md S-16, Core §2.7.3.1): the name, the name format and the friendly
 * name of its mapping, and the values of its claim, one at least: a claim the user does not hold sends no attribute.
 */
final readonly class ReleasedAttribute
{
    /**
     * @param list<AttributeValue> $values
     *
     * @throws InvalidArgumentException when it carries no value
     */
    public function __construct(
        public string $name,
        public AttributeNameFormat $nameFormat,
        public ?string $friendlyName,
        public array $values,
    ) {
        if ($values === []) {
            throw new InvalidArgumentException('An attribute an assertion carries holds one value at least (spec/saml.md S-16).');
        }
    }
}
