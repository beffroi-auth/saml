<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Upstream;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Metadata\Lexical;

final readonly class ProfileAttribute
{
    /**
     * @throws InvalidArgumentException when the name of the attribute or of the claim is not a name (S-45)
     */
    public function __construct(
        public string $name,
        public string $claim,
    ) {
        if (! Lexical::isName($name)) {
            throw new InvalidArgumentException('The name of an attribute is not empty, holds no whitespace and is at most 1024 characters (spec/saml.md S-45).');
        }
        if (! Lexical::isName($claim)) {
            throw new InvalidArgumentException('The claim an attribute fills is a claim name, not empty and with no whitespace (spec/saml.md S-45).');
        }
    }
}
