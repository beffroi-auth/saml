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
 * A member of another type is refused with its name, never coerced.
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
