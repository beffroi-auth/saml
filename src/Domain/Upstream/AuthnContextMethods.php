<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Upstream;

use function array_unique;
use function array_values;
use Beffroi\Core\Domain\Session\AuthenticationMethod;

/**
 * spec/saml.md S-57, RFC 8176 §2. A class is never read for more than it says.
 */
final class AuthnContextMethods
{
    /**
     * RFC 8176 does not register it; Microsoft's Entra writes it in the "amr" of a person a federated identity provider
     * authenticated.
     */
    public const string FEDERATED = 'fed';

    /**
     * The classes of SAML Authentication Context §3.4 that name a method of RFC 8176 §2 exactly.
     */
    private const array EXACT = [
        'urn:oasis:names:tc:SAML:2.0:ac:classes:Password' => AuthenticationMethod::PASSWORD,
        'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport' => AuthenticationMethod::PASSWORD,
        'urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard' => AuthenticationMethod::SMART_CARD,
        'urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken' => AuthenticationMethod::ONE_TIME_PASSWORD,
    ];

    private function __construct()
    {
    }

    /**
     * @return non-empty-list<AuthenticationMethod>
     */
    public static function of(string $contextClass): array
    {
        $methods = [new AuthenticationMethod(self::FEDERATED)];
        $exact = self::EXACT[$contextClass] ?? null;
        if ($exact !== null) {
            $methods[] = new AuthenticationMethod($exact);
        }

        return $methods;
    }

    /**
     * @return non-empty-list<AuthenticationMethod>
     */
    public static function everyProvable(): array
    {
        $methods = [new AuthenticationMethod(self::FEDERATED)];
        foreach (array_values(array_unique(self::EXACT)) as $exact) {
            $methods[] = new AuthenticationMethod($exact);
        }

        return $methods;
    }
}
