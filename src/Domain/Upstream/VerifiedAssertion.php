<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Upstream;

use function array_key_exists;
use DateTimeImmutable;

/**
 * What saml2-model accepted of a response of an upstream identity provider (spec/saml.md S-53), copied out of its
 * verified documents (model.md M-1), and nothing the service provider made of it yet: the NameID and whether its format
 * is persistent (S-55), the values of each attribute by its name, the AuthnInstant, the AuthnContextClassRef and the
 * SessionNotOnOrAfter of the authentication statement (S-57), and whether the assertion arrived encrypted (M-18,
 * S-54).
 */
final readonly class VerifiedAssertion
{
    /**
     * @param array<string, list<string>> $attributes the values of each attribute by its name, in document order, an
     *                                                attribute named twice merged (model.md section 6.1 step 11)
     */
    public function __construct(
        public string $nameId,
        public bool $persistent,
        public array $attributes,
        public DateTimeImmutable $authenticatedAt,
        public string $contextClass,
        public bool $encrypted,
        public ?DateTimeImmutable $sessionNotOnOrAfter = null,
    ) {
    }

    /**
     * The values of the attribute of that name, compared exactly (S-45), none when the assertion carries none.
     *
     * @return list<string>
     */
    public function values(string $attribute): array
    {
        return array_key_exists($attribute, $this->attributes) ? $this->attributes[$attribute] : [];
    }
}
