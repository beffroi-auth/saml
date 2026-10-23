<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Metadata;

use function mb_strlen;
use function preg_match;

/**
 * The lexical rules a declaration holds its names to (spec/saml.md section 6.2 step 1, section 6.10 step 1): a name is not empty, holds no
 * whitespace, no control character and no separator anywhere (M-6), is valid UTF-8, which the pattern refuses
 * otherwise, and is at most as long as a URI the model compares, counted in characters as the model counts them.
 *
 * @internal
 */
final readonly class Lexical
{
    /**
     * The length of a URI the model compares or writes, in characters (`model.md` section 7, Core §8.3.6, and the
     * entityIDType of Metadata §2.2.1).
     */
    public const int URI_LENGTH = 1024;

    public static function isName(string $value): bool
    {
        return preg_match('/^[^\s\p{Z}\p{Cc}]+\z/u', $value) === 1 && mb_strlen($value, 'UTF-8') <= self::URI_LENGTH;
    }

    /**
     * An absolute URI as far as its scheme (RFC 3986 §3.1, §4.3): the model checks the rest where it reads it.
     */
    public static function isAbsoluteUri(string $value): bool
    {
        return self::isName($value) && preg_match('/^[A-Za-z][A-Za-z0-9+.-]*:[^#]+\z/', $value) === 1;
    }
}
