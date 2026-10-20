<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\SingleLogout;

use function array_map;
use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Saml\Domain\SingleLogout\LogoutChain;
use Beffroi\Saml\Domain\SingleLogout\LogoutChainEnded;
use Beffroi\Saml\Domain\SingleLogout\LogoutChainSecret;
use Beffroi\Saml\Domain\SingleLogout\LogoutChainStarted;
use Beffroi\Saml\Domain\SingleLogout\LogoutHop;
use Beffroi\Saml\Domain\SingleLogout\LogoutProgress;
use Beffroi\Saml\Domain\SingleLogout\LogoutRequester;
use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Domain\SingleLogout\SentSignOutNotice;
use Beffroi\Saml\Domain\SingleLogout\SignOutAnswer;
use Beffroi\Saml\Domain\SingleLogout\SignOutNotice;
use Beffroi\Saml\Domain\SingleLogout\SignOutResponse;
use Beffroi\Saml\Domain\SingleLogout\SignOutStatus;
use Beffroi\Saml\Domain\SingleSignOn\PersistentNameId;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use Beffroi\Saml\Exception\LogoutRefusedException;
use Beffroi\Saml\Exception\SignOutNoticeRefusedException;
use Beffroi\Saml\Port\IdentityProviderEndpointsInterface;
use Beffroi\Saml\Port\LogoutChainRepositoryInterface;
use Beffroi\Saml\Port\PersistentIdentifierSaltInterface;
use Beffroi\Saml\Port\SessionParticipationRepositoryInterface;
use Beffroi\Saml\Port\SignOutNotifierInterface;
use Beffroi\Saml\Port\SignOutResponderInterface;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use function random_bytes;
use Throwable;

/**
 * Single Logout started by the identity provider (spec/saml.md section 6.6): once a browser has ended the sessions it
 * held (S-29), every other service provider of those sessions told through that browser, one after the other, by a
 * signed LogoutRequest (S-30, S-31), its answer read before the next one (S-33), the chain kept by the provider and
 * played once, by the browser that began it alone (S-32), and ended where its starter said, the answer to the service
 * provider that asked written last (S-34).
 */
final readonly class ProviderLogout
{
    /**
     * The octets of the reference a chain is resumed by: 256 bits, in base64url without padding, 43 characters.
     */
    private const int REFERENCE_BYTES = 32;

    public function __construct(
        private SessionParticipationRepositoryInterface $participations,
        private LogoutChainRepositoryInterface $chains,
        private AuthenticationSessionRepositoryInterface $sessions,
        private SignOutNotifierInterface $notifier,
        private SignOutResponderInterface $responder,
        private PersistentIdentifierSaltInterface $salts,
        private IdentityProviderEndpointsInterface $endpoints,
        private ClockInterface $clock,
    ) {
    }

    /**
     * Section 6.6 step 1: the chain of $sessions, ended already, the service provider of $requester left out (S-30),
     * bound to the browser that ends them by a secret drawn for it (S-32). Nothing to tell and nobody to answer ends at
     * once, nothing written.
     *
     * @param list<AuthenticationSession> $sessions
     * @param string|null $continueTo where the browser goes at the end when no service provider is to be answered
     */
    public function begin(Tenant $tenant, array $sessions, ?LogoutRequester $requester, ?string $continueTo): LogoutChainStarted|LogoutChainEnded
    {
        $hops = [];
        foreach ($sessions as $session) {
            foreach ($this->participations->ofSession($session->id) as $participation) {
                if ($participation->serviceProvider !== $requester?->serviceProvider) {
                    $hops[] = new LogoutHop($session->id, $participation->serviceProvider);
                }
            }
        }
        if ($hops === [] && $requester === null) {
            return new LogoutChainEnded($continueTo);
        }
        $reference = self::reference();
        $secret = LogoutChainSecret::draw();
        $this->chains->save(new LogoutChain(
            LogoutChain::digestOf($reference),
            $secret->digest(),
            $tenant,
            null,
            new LogoutProgress(
                array_map(static fn (AuthenticationSession $session) => $session->id, $sessions),
                $hops,
                null,
                false,
                $requester,
                $continueTo,
            ),
            LogoutChain::closesAt($this->clock->now()),
        ));

        return new LogoutChainStarted($reference, $secret, $sessions);
    }

    /**
     * Section 6.6 step 2: the chain written under $reference, open, waiting for no answer, bound to $secret, and taken
     * by this request (S-32); then the next step. A step that fails writes the chain back as it was taken, under the
     * same reference, and the failure goes up: the same request plays the step again (S-32).
     *
     * @param LogoutChainSecret|null $secret the secret the browser presents, null when it presents none
     *
     * @throws LogoutRefusedException when no open chain bound to $secret is there, or another request took it first
     * @throws KeyNotFoundException when the tenant holds no active SAML key
     * @throws KmsUnavailableException when the KMS does not answer
     * @throws RuntimeException when the salt of the tenant can neither be read nor drawn
     */
    public function resume(Tenant $tenant, string $reference, ?LogoutChainSecret $secret): PostedForm|RedirectedMessage|LogoutChainEnded
    {
        $chain = $this->chains->ofReference($tenant, $reference);
        if ($chain === null || $chain->awaitingRequest !== null || ! $chain->isOpen($this->clock->now()) || $secret === null || ! $chain->isHeldBy($secret)) {
            throw new LogoutRefusedException('No chain of logout waits to be resumed under this reference (spec/saml.md S-32).');
        }
        $this->take($chain);
        try {
            return $this->next($tenant, $chain, $chain->progress);
        } catch (Throwable $failure) {
            $this->chains->save($chain);

            throw $failure;
        }
    }

    /**
     * Section 6.6 step 4: the answer of the outstanding request, validated already (S-33), carried by the browser the
     * chain is bound to, the chain taken by this request (S-32); another status than Success counts; then the next
     * step. A next step that fails cannot be played again by that answer, which the replay store remembers: the chain,
     * the answer counted, is written back under a new reference, bound to the same browser, waiting for nothing, and
     * handed on as a chain begun is, which plays the step again (S-32, S-35).
     *
     * @throws LogoutRefusedException when the browser that carried the answer is not the one the chain is bound to, or
     *                                another request took the chain first
     */
    public function answered(Tenant $tenant, SignOutAnswer $answer): PostedForm|RedirectedMessage|LogoutChainStarted|LogoutChainEnded
    {
        $chain = $answer->chain;
        if (! $chain->isHeldBy($answer->secret)) {
            throw new LogoutRefusedException('The LogoutResponse answers no request an open chain of logout waits for (spec/saml.md S-33).');
        }
        $this->take($chain);
        $progress = $chain->progress->answered($answer->success);
        try {
            return $this->next($tenant, $chain, $progress);
        } catch (Throwable) {
            $reference = self::reference();
            $this->chains->save(new LogoutChain(LogoutChain::digestOf($reference), $chain->secret, $tenant, null, $progress, $chain->expiresAt));

            return new LogoutChainStarted($reference, $answer->secret, []);
        }
    }

    /**
     * S-36: the single logout services a chain of $session would go to, which the page whose form may end it names.
     *
     * @return list<string>
     */
    public function destinations(AuthenticationSession $session): array
    {
        $destinations = [];
        foreach ($this->participations->ofSession($session->id) as $participation) {
            $destination = $this->notifier->destination($session->tenant, $participation->serviceProvider);
            if ($destination !== null) {
                $destinations[] = $destination;
            }
        }

        return $destinations;
    }

    /**
     * A reference a chain is resumed by, drawn from random_bytes() (S-32).
     */
    private static function reference(): string
    {
        return Base64Url::encode(random_bytes(self::REFERENCE_BYTES));
    }

    /**
     * @throws LogoutRefusedException
     */
    private function take(LogoutChain $chain): void
    {
        if (! $this->chains->take($chain)) {
            throw new LogoutRefusedException('The chain of logout was played by another request (spec/saml.md S-32).');
        }
    }

    /**
     * Section 6.6 steps 3 and 5: the next service provider told, the chain written again waiting for its answer, a
     * request posted reaching where the chain goes from there (S-36); a session no longer stored, a service provider the
     * notifier cannot tell, or one whose request it cannot write, passed over (S-30); none left, the end (S-34), the
     * answer to the service provider that asked among it.
     *
     * @param LogoutChain $chain the chain taken, whose reference and secret it is written again under
     *
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     * @throws RuntimeException
     */
    private function next(Tenant $tenant, LogoutChain $chain, LogoutProgress $progress): PostedForm|RedirectedMessage|LogoutChainEnded
    {
        $now = $this->clock->now();
        $endpoints = $this->endpoints->locate($tenant);
        $identityProvider = $endpoints->metadata;
        for ($hop = $progress->next(); $hop !== null; $hop = $progress->next()) {
            $progress = $progress->withoutNext();
            $sent = $this->notice($tenant, $hop, $identityProvider, $now);
            if ($sent === null) {
                $progress = $progress->passedOver();

                continue;
            }
            $message = $sent->message instanceof PostedForm ? $this->reaching($tenant, $sent->message, $endpoints->singleLogout, $progress) : $sent->message;
            $this->chains->save(
                new LogoutChain($chain->reference, $chain->secret, $tenant, $sent->id, $progress->awaiting($hop->serviceProvider), LogoutChain::closesAt($now)),
            );

            return $message;
        }
        $requester = $progress->requester;
        if ($requester === null) {
            return new LogoutChainEnded($progress->continueTo);
        }

        return new LogoutChainEnded(null, $this->responder->answer($tenant, new SignOutResponse(
            $identityProvider,
            $requester,
            $progress->partial ? SignOutStatus::PartialLogout : SignOutStatus::Success,
            $now,
        )));
    }

    /**
     * Section 6.6 step 3: the request written for $hop, or null when it cannot be: its session no longer stored, its
     * service provider one the notifier cannot tell, or one whose request it cannot write (S-30). The salt is the
     * tenant's, read outside what passes a service provider over: a salt that cannot be read fails the step.
     *
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     * @throws RuntimeException
     */
    private function notice(Tenant $tenant, LogoutHop $hop, string $identityProvider, DateTimeImmutable $now): ?SentSignOutNotice
    {
        $session = $this->sessions->find($hop->session);
        if ($session === null) {
            return null;
        }
        $nameId = PersistentNameId::derive($hop->serviceProvider, $session->user->subject, $this->salts->saltOf($tenant))->value;
        try {
            return $this->notifier->notify($tenant, new SignOutNotice($identityProvider, $hop->serviceProvider, $nameId, $hop->session->toRfc4122(), $now));
        } catch (SignOutNoticeRefusedException) {
            return null;
        }
    }

    /**
     * S-36: the form that posts a request of the chain, which a service provider may answer by a redirection of its
     * submission, reaching the single logout service of the tenant, where that answer comes back, the single logout
     * service of each service provider left to tell, and where the chain ends, the service provider that asked or the
     * URL its starter named.
     *
     * @param string $singleLogout the single logout service of the tenant, as its metadata publish it
     */
    private function reaching(Tenant $tenant, PostedForm $form, string $singleLogout, LogoutProgress $progress): PostedForm
    {
        $reaches = [$singleLogout];
        foreach ($progress->hops as $hop) {
            $destination = $this->notifier->destination($tenant, $hop->serviceProvider);
            if ($destination !== null) {
                $reaches[] = $destination;
            }
        }
        foreach ([$progress->requester?->answerLocation, $progress->continueTo] as $end) {
            if ($end !== null) {
                $reaches[] = $end;
            }
        }

        return new PostedForm($form->action, $form->fields, $reaches);
    }
}
