<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Configuration;

use function array_values;
use Beffroi\Core\Exception\InvalidArgumentException;
use function is_array;
use function is_bool;
use function is_string;
use function sprintf;

/**
 * The members of a declaration of the configuration read as the type they are, a declaration of a service provider
 * (spec/saml.md section 6.2 step 1) or of an upstream identity provider (section 6.10 step 1): a member of another
 * type is refused with its name rather than coerced, the configuration of the application having typed most of them
 * already and a declaration built by hand having typed nothing.
 *
 * @internal
 */
final readonly class DeclarationMembers
{
    /**
     * @throws InvalidArgumentException
     */
    public static function string(mixed $value, string $member): string
    {
        return is_string($value) ? $value : throw new InvalidArgumentException(sprintf('"%s" is a string.', $member));
    }

    /**
     * @param array<array-key, mixed> $definition
     *
     * @throws InvalidArgumentException
     */
    public static function boolean(array $definition, string $member, bool $default): bool
    {
        $value = $definition[$member] ?? $default;

        return is_bool($value) ? $value : throw new InvalidArgumentException(sprintf('"%s" is a boolean.', $member));
    }

    /**
     * @param array<array-key, mixed> $definition
     *
     * @return array<array-key, mixed>
     *
     * @throws InvalidArgumentException
     */
    public static function map(array $definition, string $member): array
    {
        $value = $definition[$member] ?? [];

        return is_array($value) ? $value : throw new InvalidArgumentException(sprintf('"%s" is a map.', $member));
    }

    /**
     * @param array<array-key, mixed> $definition
     *
     * @return list<mixed>
     *
     * @throws InvalidArgumentException
     */
    public static function list(array $definition, string $member): array
    {
        return array_values(self::map($definition, $member));
    }
}
