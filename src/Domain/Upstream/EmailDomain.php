<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Upstream;

use Beffroi\Core\Exception\InvalidArgumentException;
use function idn_to_ascii;
use const IDNA_CHECK_BIDI;
use const IDNA_CHECK_CONTEXTJ;
use const IDNA_NONTRANSITIONAL_TO_ASCII;
use const IDNA_USE_STD3_RULES;
use const INTL_IDNA_VARIANT_UTS46;
use function is_array;
use function preg_match;
use function sprintf;
use function strlen;
use function strrpos;
use function strtolower;
use function substr;

/**
 * An e-mail domain an upstream identity provider answers for (spec/saml.md S-44): the whole part of an address after
 * its "@", and nothing under it. A name of the DNS, labels of letters, digits and hyphens, neither beginning nor
 * ending with a hyphen, 63 characters at most, two labels at least, the last beginning with a letter so that an IPv4
 * address is none, 253 characters at most (RFC 1035 §2.3.4, RFC 1123 §2.1), a name outside ASCII written as its
 * A-label (RFC 5890 §2.3.2.1), as the core's Host takes a name. Read without regard to case and kept in lower case
 * (RFC 4343), so that two spellings are one domain.
 *
 * The domain of an address is compared with a declared one through ofAddress() and through nothing else: the core
 * keeps an address as it was typed, its case and a name outside ASCII included, which a declared domain is not.
 */
final readonly class EmailDomain
{
    /**
     * The length of a name of the DNS in its textual form (RFC 1035 §2.3.4, less the final dot).
     */
    public const int MAX_LENGTH = 253;

    private const string NAME = '/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\z/';

    /**
     * What the IDNA of UTS #46 is asked: non-transitional, the rules of STD3 for the characters of a name, and the
     * checks of bidirectional text and of joiners (UTS #46 §4).
     */
    private const int IDNA = IDNA_NONTRANSITIONAL_TO_ASCII | IDNA_USE_STD3_RULES | IDNA_CHECK_BIDI | IDNA_CHECK_CONTEXTJ;

    /**
     * The domain in lower case.
     */
    public string $value;

    /**
     * @throws InvalidArgumentException when it is not a name of the DNS of two labels at least (S-44)
     */
    public function __construct(string $domain)
    {
        $value = strtolower($domain);
        if (strlen($value) > self::MAX_LENGTH || preg_match(self::NAME, $value) !== 1) {
            throw new InvalidArgumentException(sprintf(
                '"%s" is no e-mail domain: a name of the DNS of two labels at least, of letters, digits and hyphens, a name outside ASCII written as its A-label (spec/saml.md S-44).',
                $domain,
            ));
        }
        $this->value = $value;
    }

    /**
     * The domain of an address, the whole part after its last "@", as a declared domain is written (S-44): through the
     * IDNA of UTS #46, which writes a name outside ASCII as its A-label and lower-cases it, then the rule of a declared
     * domain. Neither refusal names the address, which is a person's.
     *
     * @throws InvalidArgumentException when the address holds no "@", or its domain cannot be converted or is no name
     *                                  of the DNS of two labels at least once converted
     */
    public static function ofAddress(string $address): self
    {
        $at = strrpos($address, '@');
        $domain = $at === false ? '' : substr($address, $at + 1);
        if ($domain === '') {
            throw new InvalidArgumentException('An address holds a domain after its "@" (spec/saml.md S-44).');
        }
        $ascii = idn_to_ascii($domain, self::IDNA, INTL_IDNA_VARIANT_UTS46, $info);
        if ($ascii === false || ! is_array($info) || ($info['errors'] ?? null) !== 0) {
            throw new InvalidArgumentException('The domain of an address cannot be written as a name of the DNS by the IDNA of UTS #46 (spec/saml.md S-44).');
        }
        try {
            return new self($ascii);
        } catch (InvalidArgumentException $refusal) {
            throw new InvalidArgumentException('The domain of an address is no name of the DNS of two labels at least (spec/saml.md S-44).', 0, $refusal);
        }
    }
}
