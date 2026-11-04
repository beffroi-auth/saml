<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Upstream;

use function array_key_exists;
use DateTimeImmutable;

final readonly class VerifiedAssertion
{
    /**
     * @param array<string, list<string>> $attributes the values by attribute name, in document order
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
     * @return list<string>
     */
    public function values(string $attribute): array
    {
        return array_key_exists($attribute, $this->attributes) ? $this->attributes[$attribute] : [];
    }
}
