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
 * spec/saml.md section 6.5, S-22, S-23, S-24, S-25, S-27, S-32, S-34
 *
 * The key that signs the answer is opened first: a key that cannot be opened ends nothing and remembers nothing, so
 * that the same message is accepted once the key or the KMS is back.
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
     *
     * @throws LogoutRefusedException when the message is refused: no session ended, no SAML answer
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
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
     * @param array<array-key, mixed> $fields
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
     * Section 6.5 steps 2 to 4, S-34
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
     * S-24
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
     * S-24
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
     * S-24, S-13
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
