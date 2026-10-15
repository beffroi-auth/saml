<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

/**
 * An accepted LogoutRequest as the identity provider handles it (spec/saml.md section 6.5): the entity ID of the
 * service provider that sent it, its ID, the NameID of the principal as it was received (S-24), the session indexes it
 * names, the RelayState as saml2-bindings decoded it, and where its answer goes, the binding and the URL of the
 * SingleLogoutService of the accepted metadata resolved when it was received (S-27), never a URL of the request.
 */
final readonly class SignOutRequest
{
    /**
     * @param list<string> $sessionIndexes as read, at most the 16 of the model (section 7)
     * @param string $answerBinding the URI of the binding of the SingleLogoutService the answer goes to
     * @param string $answerLocation its ResponseLocation, or else its Location (SAML Metadata §2.2.2)
     */
    public function __construct(
        public string $serviceProvider,
        public string $id,
        public string $nameId,
        public string $nameIdFormat,
        public ?string $nameQualifier,
        public ?string $spNameQualifier,
        public array $sessionIndexes,
        public ?string $relayState,
        public string $answerBinding,
        public string $answerLocation,
    ) {
    }
}
