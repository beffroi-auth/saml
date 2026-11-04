<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleSignOn;

use function array_is_list;
use Beffroi\Core\Exception\InvalidArgumentException;
use function is_array;
use function is_bool;
use function is_int;
use function is_string;
use function preg_match;

/**
 * spec/saml.md S-16, XML 1.0 §2.2. Refused when it is built: the DOM cuts a string at its first NUL, so a value
 * written past it would be signed short.
 */
final readonly class AttributeValue
{
    /**
     * The Char production of XML 1.0 §2.2
     */
    private const string CHAR = '/^[\x{9}\x{A}\x{D}\x{20}-\x{D7FF}\x{E000}-\x{FFFD}\x{10000}-\x{10FFFF}]*$/Du';

    /**
     * @throws InvalidArgumentException when the value holds a character outside Char or bytes that are not UTF-8
     */
    public function __construct(
        public string $value,
    ) {
        if (preg_match(self::CHAR, $value) !== 1) {
            throw new InvalidArgumentException('An attribute value holds only the characters of XML 1.0, in UTF-8: no NUL, no other control character but the tab, the line feed and the carriage return, no surrogate, no U+FFFE or U+FFFF (spec/saml.md S-16).');
        }
    }

    /**
     * @return list<self>
     *
     * @throws InvalidArgumentException
     */
    public static function ofClaim(mixed $claim): array
    {
        if (! is_array($claim)) {
            return [self::ofScalar($claim)];
        }
        if (! array_is_list($claim)) {
            throw new InvalidArgumentException('A claim whose value is a JSON object is not the value of an attribute (spec/saml.md S-16).');
        }
        $values = [];
        foreach ($claim as $member) {
            $values[] = self::ofScalar($member);
        }

        return $values;
    }

    /**
     * @throws InvalidArgumentException
     */
    private static function ofScalar(mixed $value): self
    {
        if (is_string($value)) {
            return new self($value);
        }
        if (is_int($value)) {
            return new self((string) $value);
        }
        if (is_bool($value)) {
            return new self($value ? 'true' : 'false');
        }

        throw new InvalidArgumentException('A value of a claim is a string, an integer or a boolean to be the value of an attribute (spec/saml.md S-16).');
    }
}
