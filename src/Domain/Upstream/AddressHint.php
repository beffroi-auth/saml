<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Upstream;

use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Exception\InvalidArgumentException;
use function in_array;
use function preg_match;
use function rawurlencode;
use function sprintf;
use function str_contains;
use function strpos;
use function strtolower;
use function substr;

/**
 * spec/saml.md S-68. SAML has no such hint (Core §3.4.1): it is a parameter of the provider, never read back, the
 * person being who the signed assertion names.
 */
final readonly class AddressHint
{
    public const int MAX_PARAMETER_LENGTH = 64;

    /**
     * RFC 3986 §2.3
     */
    private const string UNRESERVED = '/^[A-Za-z0-9._~-]{1,64}\z/';

    /**
     * bindings.md B-1
     */
    private const array BINDING_PARAMETERS = ['samlrequest', 'samlresponse', 'samlencoding', 'relaystate', 'sigalg', 'signature'];

    /**
     * @throws InvalidArgumentException when the name is not one to 64 unreserved characters, or is one of the
     *                                  parameters of the binding
     */
    public function __construct(
        public string $parameter,
        public EmailAddress $address,
    ) {
        self::assertParameter($parameter);
    }

    /**
     * S-68: none of the parameters of the binding, whatever its case, which a provider that reads its query so would
     * take for one of them.
     *
     * @throws InvalidArgumentException
     */
    public static function assertParameter(string $parameter): void
    {
        if (preg_match(self::UNRESERVED, $parameter) !== 1) {
            throw new InvalidArgumentException(sprintf(
                'The parameter of the address is one to %d unreserved characters of RFC 3986 (spec/saml.md S-68).',
                self::MAX_PARAMETER_LENGTH,
            ));
        }
        if (in_array(strtolower($parameter), self::BINDING_PARAMETERS, true)) {
            throw new InvalidArgumentException(sprintf(
                'The parameter of the address "%s" is a parameter of the binding (spec/saml.md S-68).',
                $parameter,
            ));
        }
    }

    /**
     * S-68. On the URL of HTTP-Redirect, it comes after the Signature, outside the octets the signature covers
     * (Bindings §3.4.4.1).
     */
    public function appendedTo(string $url): string
    {
        $fragment = strpos($url, '#');
        $head = $fragment === false ? $url : substr($url, 0, $fragment);
        $tail = $fragment === false ? '' : substr($url, $fragment);

        return $head . (str_contains($head, '?') ? '&' : '?') . $this->parameter . '=' . rawurlencode($this->address->value) . $tail;
    }
}
