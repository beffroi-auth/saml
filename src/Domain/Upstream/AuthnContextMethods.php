<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Upstream;

use function array_unique;
use function array_values;
use Beffroi\Core\Domain\Session\AuthenticationMethod;

/**
 * What a login of an upstream identity provider proves, in the values of RFC 8176 §2 (spec/saml.md S-57): "fed", a
 * federated assertion, which RFC 8176 does not register and Microsoft's Entra writes for one, and the
 * AuthnContextClassRef of the assertion where its meaning is the method's exactly (SAML Authentication Context §3.4):
 * Password and PasswordProtectedTransport are a password, Smartcard a smart card, TimeSyncToken a one-time password.
 * Any other class says nothing more: a class is never read for more than it says, X509, Kerberos or a class of another
 * vocabulary naming no method of RFC 8176 exactly.
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
     * @param string $contextClass the AuthnContextClassRef of the assertion, compared exactly
     *
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
     * Every method a login of an upstream identity provider may prove, each once, "fed" first: what the provider
     * announces of that login.
     *
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
