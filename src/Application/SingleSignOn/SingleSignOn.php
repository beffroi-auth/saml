<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\SingleSignOn;

use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Saml\Domain\Event\ServiceProviderSignedIn;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProvider;
use Beffroi\Saml\Domain\SingleSignOn\PersistentNameId;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use Beffroi\Saml\Domain\SingleSignOn\SignOnFailure;
use Beffroi\Saml\Domain\SingleSignOn\SignOnRequest;
use Beffroi\Saml\Domain\SingleSignOn\SignOnResponse;
use Beffroi\Saml\Domain\SingleSignOn\SignOnStatus;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Exception\SignOnRefusedException;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Port\AuthnRequestReceiverInterface;
use Beffroi\Saml\Port\IdentityProviderEndpointsInterface;
use Beffroi\Saml\Port\PersistentIdentifierSaltInterface;
use Beffroi\Saml\Port\ServiceProviderMetadataReaderInterface;
use Beffroi\Saml\Port\ServiceProvidersInterface;
use Beffroi\Saml\Port\SignOnResponderInterface;
use DateTimeImmutable;
use function in_array;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * spec/saml.md section 6.4, S-19, S-26
 */
final readonly class SingleSignOn
{
    /**
     * The formats of a NameIDPolicy answered with the persistent identifier (SAML Core §8.3.1, §8.3.7).
     */
    private const array ANSWERED_FORMATS = [
        PersistentNameId::FORMAT,
        'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    ];

    public function __construct(
        private AuthnRequestReceiverInterface $receiver,
        private SignOnResponderInterface $responder,
        private ServiceProvidersInterface $serviceProviders,
        private AttributeRelease $attributes,
        private PersistentIdentifierSaltInterface $salts,
        private IdentityProviderEndpointsInterface $endpoints,
        private ClockInterface $clock,
        private AcceptedMetadataRepositoryInterface $acceptedMetadata,
        private ServiceProviderMetadataReaderInterface $metadataReader,
        private EventDispatcherInterface $events,
    ) {
    }

    /**
     * @param string $queryString the raw query string (section 6.8)
     *
     * @throws SignOnRefusedException when the request is refused: no SAML answer
     */
    public function receiveRedirect(Tenant $tenant, string $queryString): SignOnRequest
    {
        $request = $this->receiver->redirect($tenant, $queryString);
        $this->encryptionKey($tenant, $this->declaration($tenant, $request));

        return $request;
    }

    /**
     * @param array<array-key, mixed> $fields
     *
     * @throws SignOnRefusedException
     */
    public function receivePost(Tenant $tenant, array $fields): SignOnRequest
    {
        $request = $this->receiver->post($tenant, $fields);
        $this->encryptionKey($tenant, $this->declaration($tenant, $request));

        return $request;
    }

    /**
     * Null when the browser has to sign in first (section 6.4 step 4, S-17).
     *
     * @throws SignOnRefusedException
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     * @throws RuntimeException when the salt of the tenant can neither be read nor drawn
     */
    public function answer(Tenant $tenant, SignOnRequest $request, ?AuthenticationSession $session, RequestContext $context): ?PostedForm
    {
        $now = $this->clock->now();
        if ($now >= $request->expiresAt()) {
            throw new SignOnRefusedException('The request waited longer than the ten minutes it may wait for a login (spec/saml.md S-18).');
        }
        $declaration = $this->declaration($tenant, $request);
        $identityProvider = $this->endpoints->locate($tenant)->metadata;
        $status = self::refusal($request);
        if ($status === null) {
            $answering = self::answering($tenant, $request, $session, $now);
            if ($answering !== null) {
                return $this->success($tenant, $declaration, $identityProvider, $request, $answering, $now, $context);
            }
            if (! $request->isPassive) {
                return null;
            }
            $status = SignOnStatus::NoPassive;
        }

        return $this->responder->failure($tenant, new SignOnFailure($identityProvider, $request, $status, $now));
    }

    /**
     * Section 6.4 steps 5 to 7, S-26
     *
     * @throws SignOnRefusedException
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     * @throws RuntimeException
     */
    private function success(
        Tenant $tenant,
        ServiceProvider $declaration,
        string $identityProvider,
        SignOnRequest $request,
        AuthenticationSession $session,
        DateTimeImmutable $now,
        RequestContext $context,
    ): PostedForm {
        $user = $session->user;
        $form = $this->responder->success($tenant, new SignOnResponse(
            $identityProvider,
            $request,
            PersistentNameId::derive($declaration->entityId, $user->subject, $this->salts->saltOf($tenant)),
            $this->attributes->of($declaration, $user),
            $session->id->toRfc4122(),
            $session->authenticatedAt(),
            $now,
            $this->encryptionKey($tenant, $declaration),
        ));
        $this->events->dispatch(new ServiceProviderSignedIn($now, $tenant, $session->id, $declaration->entityId, $user->subject, $context));

        return $form;
    }

    /**
     * Section 6.4 step 4
     */
    private static function refusal(SignOnRequest $request): ?SignOnStatus
    {
        if ($request->nameIdFormat !== null && ! in_array($request->nameIdFormat, self::ANSWERED_FORMATS, true)) {
            return SignOnStatus::InvalidNameIdPolicy;
        }

        return $request->authnContextRequested ? SignOnStatus::NoAuthnContext : null;
    }

    /**
     * S-17
     *
     * The core keeps a proof to the second, so the instant of the request is compared at that precision.
     */
    private static function answering(Tenant $tenant, SignOnRequest $request, ?AuthenticationSession $session, DateTimeImmutable $now): ?AuthenticationSession
    {
        if ($session === null || ! $session->tenant->equals($tenant) || ! $session->isActive($now)) {
            return null;
        }

        return ! $request->forceAuthn || $session->authenticatedAt()->getTimestamp() >= $request->receivedAt->getTimestamp() ? $session : null;
    }

    /**
     * Section 6.4 step 2
     *
     * @throws SignOnRefusedException
     */
    private function declaration(Tenant $tenant, SignOnRequest $request): ServiceProvider
    {
        return (
            $this->serviceProviders->find(
                $tenant,
                $request->serviceProvider,
            ) ?? throw new SignOnRefusedException('The service provider of the request is no longer declared (spec/saml.md section 6.4 step 2).')
        );
    }

    /**
     * S-19, section 6.4 steps 2 and 7
     *
     * Null for a provider that does not ask for encryption; one that asks and has no key for it is refused, so that
     * nothing is sent in clear.
     *
     * @throws SignOnRefusedException
     */
    private function encryptionKey(Tenant $tenant, ServiceProvider $declaration): ?Certificate
    {
        if (! $declaration->encryptAssertions) {
            return null;
        }
        $accepted = $this->acceptedMetadata->find($tenant, $declaration->entityId);
        try {
            $certificate = $accepted === null ? null : $this->metadataReader->readTrusted($accepted->document)->encryptionCertificate();
        } catch (MetadataRefusedException) {
            $certificate = null;
        }

        return $certificate ?? throw new SignOnRefusedException('The service provider asks for its assertions encrypted and no key for encryption is read back from its accepted metadata: none is sent in clear (spec/saml.md S-19).');
    }
}
