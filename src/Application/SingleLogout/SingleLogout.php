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
use Beffroi\Saml\Domain\SingleLogout\LogoutChainEnded;
use Beffroi\Saml\Domain\SingleLogout\LogoutChainSecret;
use Beffroi\Saml\Domain\SingleLogout\LogoutChainStarted;
use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Domain\SingleLogout\SignOutAnswer;
use Beffroi\Saml\Domain\SingleLogout\SignOutRequest;
use Beffroi\Saml\Domain\SingleLogout\SignOutResponse;
use Beffroi\Saml\Domain\SingleLogout\SignOutStatus;
use Beffroi\Saml\Domain\SingleSignOn\PersistentNameId;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use Beffroi\Saml\Exception\LogoutRefusedException;
use Beffroi\Saml\Port\IdentityProviderEndpointsInterface;
use Beffroi\Saml\Port\LogoutMessageReceiverInterface;
use Beffroi\Saml\Port\PersistentIdentifierSaltInterface;
use Beffroi\Saml\Port\SignOutResponderInterface;
use function hash_equals;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

/**
 * The single logout service of the tenant, from the message the application received to what the browser is given (spec/
 * saml.md section 6.5): the key that signs the answer opened first, then a request of a service provider accepted,
 * once (S-22, S-23), the sessions it names ended when their user is the principal it names (S-24), as every session of
 * the core ends (S-25), then the other service providers of those sessions told before the answer is written to the
 * single logout service of the accepted metadata of the service provider that asked (S-27, S-34); or the answer of a
 * service provider a chain waits for, carried by the browser the chain is bound to, handed to the chain (section 6.6
 * step 4, S-32). A key that cannot be opened ends nothing and remembers nothing, so that the same message is accepted
 * once the key or the KMS is back.
 */
final readonly class SingleLogout
{
    public function __construct(
        private LogoutMessageReceiverInterface $receiver,
        private SignOutResponderInterface $responder,
        private AuthenticationSessionRepositoryInterface $sessions,
        private SessionTerminator $terminator,
        private PersistentIdentifierSaltInterface $salts,
        private IdentityProviderEndpointsInterface $endpoints,
        private ClockInterface $clock,
        private ProviderLogout $chains,
    ) {
    }

    /**
     * @param string $queryString the raw query string (section 6.8)
     * @param LogoutChainSecret|null $secret the secret of a chain the browser presents, which the answer of a service
     *                                       provider is read with (S-32, S-33), null when it presents none
     *
     * @throws LogoutRefusedException when the message is refused: no session ended, no SAML answer
     * @throws KeyNotFoundException when the tenant holds no active SAML key: nothing read, ended or remembered
     * @throws KmsUnavailableException when the KMS does not answer
     * @throws RuntimeException when the salt of the tenant can neither be read nor drawn
     */
    public function redirect(
        Tenant $tenant,
        string $queryString,
        RequestContext $context,
        ?LogoutChainSecret $secret,
    ): PostedForm|RedirectedMessage|LogoutChainStarted|LogoutChainEnded {
        $this->responder->open($tenant);

        return $this->handle($tenant, $this->receiver->redirect($tenant, $queryString, $secret), $context);
    }

    /**
     * @param array<array-key, mixed> $fields the fields of the form (section 6.8)
     * @param LogoutChainSecret|null $secret the secret of a chain the browser presents, null when it presents none
     *
     * @throws LogoutRefusedException
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     * @throws RuntimeException
     */
    public function post(
        Tenant $tenant,
        array $fields,
        RequestContext $context,
        ?LogoutChainSecret $secret,
    ): PostedForm|RedirectedMessage|LogoutChainStarted|LogoutChainEnded {
        $this->responder->open($tenant);

        return $this->handle($tenant, $this->receiver->post($tenant, $fields, $secret), $context);
    }

    /**
     * @throws LogoutRefusedException when the chain an answer is for is bound to another browser, or was played by
     *                                another request (S-32)
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     * @throws RuntimeException
     */
    private function handle(
        Tenant $tenant,
        SignOutRequest|SignOutAnswer $received,
        RequestContext $context,
    ): PostedForm|RedirectedMessage|LogoutChainStarted|LogoutChainEnded {
        if ($received instanceof SignOutAnswer) {
            return $this->chains->answered($tenant, $received);
        }

        return $this->answer($tenant, $received, $context);
    }

    /**
     * Section 6.5 steps 2 to 4: the answer written at once when no session ended, after the chain otherwise (S-34).
     *
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     * @throws RuntimeException
     */
    private function answer(Tenant $tenant, SignOutRequest $request, RequestContext $context): PostedForm|RedirectedMessage|LogoutChainStarted
    {
        $now = $this->clock->now();
        $identityProvider = $this->endpoints->locate($tenant)->metadata;
        $named = $this->named($tenant, $request);
        $status = $this->status($tenant, $identityProvider, $request, $named);
        if ($status === SignOutStatus::Success && $named !== []) {
            foreach ($named as $session) {
                $this->terminator->end($session, SessionEnd::RelyingParty, $context);
            }
            $started = $this->chains->begin($tenant, $named, $request->requester(), null);
            if ($started instanceof LogoutChainStarted) {
                return $started;
            }
        }

        return $this->responder->answer($tenant, new SignOutResponse($identityProvider, $request->requester(), $status, $now));
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
