<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Upstream;

use Beffroi\Core\Exception\InvalidArgumentException;
use function preg_match;
use function sprintf;
use function strlen;
use function strtolower;

/**
 * An e-mail domain an upstream identity provider answers for (spec/saml.md S-44): the whole part of an address after
 * its "@", and nothing under it. A name of the DNS, labels of letters, digits and hyphens, neither beginning nor
 * ending with a hyphen, 63 characters at most, two labels at least, the last beginning with a letter so that an IPv4
 * address is none, 253 characters at most (RFC 1035 §2.3.4, RFC 1123 §2.1), a name outside ASCII written as its
 * A-label (RFC 5890 §2.3.2.1), as the core's Host takes a name. Read without regard to case and kept in lower case
 * (RFC 4343), so that two spellings are one domain.
 */
final readonly class EmailDomain
{
    /**
     * The length of a name of the DNS in its textual form (RFC 1035 §2.3.4, less the final dot).
     */
    public const int MAX_LENGTH = 253;

    private const string NAME = '/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\z/';

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
}
