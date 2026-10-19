<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\SingleLogout;

use Beffroi\Core\Application\Authentication\SessionTerminator;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Domain\SingleLogout\SignOutRequest;
use Beffroi\Saml\Domain\SingleLogout\SignOutResponse;
use Beffroi\Saml\Domain\SingleLogout\SignOutStatus;
use Beffroi\Saml\Domain\SingleSignOn\PersistentNameId;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use Beffroi\Saml\Exception\LogoutRefusedException;
use Beffroi\Saml\Port\IdentityProviderEndpointsInterface;
use Beffroi\Saml\Port\LogoutRequestReceiverInterface;
use Beffroi\Saml\Port\PersistentIdentifierSaltInterface;
use Beffroi\Saml\Port\SignOutResponderInterface;
use function hash_equals;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Single Logout started by a service provider, from the request the bundle received to the answer the browser
 * carries back (spec/saml.md section 6.5): the key that signs the answer opened first, then the request accepted, once
 * (S-22, S-23), the sessions it names ended when their user is the principal it names (S-24), as every session of the
 * core ends (S-25), and the answer written to the single logout service of the accepted metadata of the service
 * provider (S-27). A key that cannot be opened ends nothing and remembers nothing, so that the same request is accepted
 * once the key or the KMS is back.
 */
final readonly class SingleLogout
{
    public function __construct(
        private LogoutRequestReceiverInterface $receiver,
        private SignOutResponderInterface $responder,
        private AuthenticationSessionRepositoryInterface $sessions,
        private SessionTerminator $terminator,
        private PersistentIdentifierSaltInterface $salts,
        private IdentityProviderEndpointsInterface $endpoints,
        private ClockInterface $clock,
    ) {
    }

    /**
     * @param string $queryString the raw query string (section 6.8)
     *
     * @throws LogoutRefusedException when the request is refused: no session ended, no SAML answer
     * @throws KeyNotFoundException when the tenant holds no active SAML key: nothing read, ended or remembered
     * @throws KmsUnavailableException when the KMS does not answer
     * @throws RuntimeException when the salt of the tenant can neither be read nor drawn
     */
    public function redirect(Tenant $tenant, string $queryString, RequestContext $context): PostedForm|RedirectedMessage
    {
        $this->responder->open($tenant);

        return $this->answer($tenant, $this->receiver->redirect($tenant, $queryString), $context);
    }

    /**
     * @param array<array-key, mixed> $fields the fields of the form (section 6.8)
     *
     * @throws LogoutRefusedException
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     * @throws RuntimeException
     */
    public function post(Tenant $tenant, array $fields, RequestContext $context): PostedForm|RedirectedMessage
    {
        $this->responder->open($tenant);

        return $this->answer($tenant, $this->receiver->post($tenant, $fields), $context);
    }

    /**
     * Section 6.5 steps 2 to 4.
     *
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     * @throws RuntimeException
     */
    private function answer(Tenant $tenant, SignOutRequest $request, RequestContext $context): PostedForm|RedirectedMessage
    {
        $now = $this->clock->now();
        $identityProvider = $this->endpoints->locate($tenant)->metadata;
        $named = $this->named($tenant, $request);
        $status = $this->status($tenant, $identityProvider, $request, $named);
        if ($status === SignOutStatus::Success) {
            foreach ($named as $session) {
                $this->terminator->end($session, SessionEnd::RelyingParty, $context);
            }
        }

        return $this->responder->answer($tenant, new SignOutResponse($identityProvider, $request, $status, $now));
    }

    /**
     * S-24: the active sessions of the tenant the session indexes name, a session index being the ID of a session; one
     * that names none of them, or one that has ended, is ended already.
     *
     * @return list<AuthenticationSession>
     */
    private function named(Tenant $tenant, SignOutRequest $request): array
    {
        $now = $this->clock->now();
        $named = [];
        foreach ($request->sessionIndexes as $sessionIndex) {
            if (! Uuid::isValid($sessionIndex)) {
                continue;
            }
            $session = $this->sessions->find(Uuid::fromString($sessionIndex));
            if ($session !== null && $session->tenant->equals($tenant) && $session->isActive($now)) {
                $named[] = $session;
            }
        }

        return $named;
    }

    /**
     * S-24: a request naming no session index is not supported; one naming a session of another principal ends
     * nothing; otherwise every session named ends.
     *
     * @param list<AuthenticationSession> $named
     *
     * @throws RuntimeException
     */
    private function status(Tenant $tenant, string $identityProvider, SignOutRequest $request, array $named): SignOutStatus
    {
        if ($request->sessionIndexes === []) {
            return SignOutStatus::RequestUnsupported;
        }
        foreach ($named as $session) {
            if (! $this->isPrincipal($tenant, $identityProvider, $request, $session)) {
                return SignOutStatus::UnknownPrincipal;
            }
        }

        return SignOutStatus::Success;
    }

    /**
     * S-24, S-13: the NameID of the request is the persistent identifier of the user of the session at its service
     * provider, qualified, when it is, by the two entities.
     *
     * @throws RuntimeException
     */
    private function isPrincipal(Tenant $tenant, string $identityProvider, SignOutRequest $request, AuthenticationSession $session): bool
    {
        if ($request->nameIdFormat !== PersistentNameId::FORMAT) {
            return false;
        }
        if ($request->nameQualifier !== null && $request->nameQualifier !== $identityProvider) {
            return false;
        }
        if ($request->spNameQualifier !== null && $request->spNameQualifier !== $request->serviceProvider) {
            return false;
        }
        $expected = PersistentNameId::derive($request->serviceProvider, $session->user->subject, $this->salts->saltOf($tenant));

        return hash_equals($expected->value, $request->nameId);
    }
}
