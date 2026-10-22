<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Upstream;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Metadata\Lexical;
use function count;
use function is_string;
use function mb_strlen;
use function preg_match;
use function sprintf;

/**
 * The attribute that carries the groups of a person in the assertions of an upstream identity provider, and the name
 * of a group of the tenant each of its values stands for (spec/saml.md S-45). A value the map does not name is no
 * group, and no group is created from what a provider sends: the groups are the tenant's, found by their name when a
 * person signs in (issue #782), and nothing here reads one.
 */
final readonly class GroupMapping
{
    /**
     * The attributes per statement of `model.md` section 7: an assertion carries no more values (section 7).
     */
    public const int MAX_VALUES = 256;

    /**
     * @param array<array-key, string> $groups the name of a group of the tenant by value of the attribute, compared
     *                                         exactly; a value of digits alone is an integer key, as PHP keeps it
     *
     * @throws InvalidArgumentException when the attribute, a value or a group is not one (S-45)
     */
    public function __construct(
        public string $attribute,
        private array $groups,
    ) {
        if (! Lexical::isName($attribute)) {
            throw new InvalidArgumentException('The name of the attribute of the groups is not empty, holds no whitespace and is at most 1024 characters (spec/saml.md S-45).');
        }
        if (count($groups) > self::MAX_VALUES) {
            throw new InvalidArgumentException('The groups of an identity provider map 256 values at most (spec/saml.md section 7).');
        }
        foreach ($groups as $value => $group) {
            self::assertValue((string) $value);
            if ($group === '') {
                throw new InvalidArgumentException(sprintf('The value "%s" of the groups names no group (spec/saml.md S-45).', $value));
            }
        }
    }

    /**
     * The name of the group of the tenant a value of the attribute stands for, compared exactly, or null when the map
     * names none.
     */
    public function groupOf(string $value): ?string
    {
        $group = $this->groups[$value] ?? null;

        return is_string($group) ? $group : null;
    }

    /**
     * @throws InvalidArgumentException
     */
    private static function assertValue(string $value): void
    {
        if ($value === '' || mb_strlen($value, 'UTF-8') > Lexical::URI_LENGTH || preg_match('/^\P{Cc}+\z/u', $value) !== 1) {
            throw new InvalidArgumentException('A value of the groups is not empty, holds no control character and is at most 1024 characters (spec/saml.md S-45).');
        }
    }
}
