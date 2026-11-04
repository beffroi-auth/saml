<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Metadata;

use Beffroi\Core\Domain\Encoding\Host;
use function preg_match;

/**
 * spec/saml.md S-11, S-43. Narrower than the reg-name of RFC 3986: its origin goes into a Content-Security-Policy,
 * where a ";" ends a directive and a "," a policy.
 */
final readonly class EndpointLocation
{
    private const string HTTPS_ON_A_HOST = '~^https://' . Host::PATTERN . '(?::[0-9]{1,5})?(?:[/?#]|\z)~i';

    public static function isHttpsOnAHost(string $location): bool
    {
        return preg_match(self::HTTPS_ON_A_HOST, $location) === 1;
    }
}
