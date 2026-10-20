<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\ServiceProvider;

use Beffroi\Core\Domain\Encoding\Host;
use function preg_match;

/**
 * Where the identity provider sends a browser for a service provider (spec/saml.md S-11): the Location of an
 * md:AssertionConsumerService, the Location and the ResponseLocation of an md:SingleLogoutService, which become the
 * action of a form, the target of a redirection and, by their origin, a source of the Content-Security-Policy of the
 * page that sends the browser there (S-36).
 *
 * An https URL, its scheme compared without regard to case (RFC 3986 §3.1), its authority a host and an optional port
 * and nothing else: no userinfo, and a host of the core's rule (Host), a name for the DNS of letters, digits, hyphens
 * and dots, which an IPv4 address is too, or an IPv6 literal between brackets, the rule a client of OpenID Connect is
 * held to as well. The reg-name of RFC 3986 admits more, its sub-delimiters among them, the ";" that ends a directive
 * of a policy and the "," that ends a policy. saml2-model, a model of the standard, accepts any absolute URI (M-6);
 * what an identity provider hands a browser is narrower.
 */
final readonly class EndpointLocation
{
    private const string HTTPS_ON_A_HOST = '~^https://' . Host::PATTERN . '(?::[0-9]{1,5})?(?:[/?#]|\z)~i';

    public static function isHttpsOnAHost(string $location): bool
    {
        return preg_match(self::HTTPS_ON_A_HOST, $location) === 1;
    }
}
