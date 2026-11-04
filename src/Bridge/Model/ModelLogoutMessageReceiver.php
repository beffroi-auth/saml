<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\SingleLogout\LogoutChainSecret;
use Beffroi\Saml\Domain\SingleLogout\SignOutAnswer;
use Beffroi\Saml\Domain\SingleLogout\SignOutRequest;
use Beffroi\Saml\Exception\LogoutRefusedException;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Port\IdentityProviderEndpointsInterface;
use Beffroi\Saml\Port\LogoutChainRepositoryInterface;
use Beffroi\Saml\Port\LogoutMessageReceiverInterface;
use Beffroi\Saml\Port\ReplayStoreInterface;
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\ReceivedLogoutRequest;
use Beffroi\Saml2\Bindings\ReceivedLogoutResponse;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\LogoutRequestValidator;
use Beffroi\Saml2\Model\Validation\LogoutResponseValidator;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;
use Psr\Clock\ClockInterface;

/**
 * spec/saml.md section 6.5 step 1, section 6.6 step 4
 */
final readonly class ModelLogoutMessageReceiver implements LogoutMessageReceiverInterface
{
    private Loader $loader;

    private RedirectReceiver $redirect;

    private PostReceiver $post;

    public function __construct(
        private DeclaredServiceProviderReader $serviceProviders,
        private IdentityProviderEndpointsInterface $endpoints,
        private ReplayStoreInterface $replay,
        private ClockInterface $clock,
        private LogoutChainRepositoryInterface $chains,
    ) {
        $this->loader = SamlLoader::create();
        $this->redirect = new RedirectReceiver($this->loader);
        $this->post = new PostReceiver($this->loader);
    }

    public function redirect(Tenant $tenant, string $queryString, ?LogoutChainSecret $secret): SignOutRequest|SignOutAnswer
    {
        try {
            $received = $this->redirect->logoutMessage($queryString);
        } catch (RefusedXml $exception) {
            throw new LogoutRefusedException($exception->getMessage(), 0, $exception);
        }

        return $this->validated($tenant, $received, $secret);
    }

    public function post(Tenant $tenant, array $fields, ?LogoutChainSecret $secret): SignOutRequest|SignOutAnswer
    {
        try {
            $received = $this->post->logoutMessage($fields);
        } catch (RefusedXml $exception) {
            throw new LogoutRefusedException($exception->getMessage(), 0, $exception);
        }

        return $this->validated($tenant, $received, $secret);
    }

    /**
     * @throws LogoutRefusedException
     */
    private function validated(Tenant $tenant, ReceivedLogoutRequest|ReceivedLogoutResponse $received, ?LogoutChainSecret $secret): SignOutRequest|SignOutAnswer
    {
        if ($received instanceof ReceivedLogoutResponse) {
            return $this->answer($tenant, $received, $secret);
        }

        return $this->request($tenant, $received);
    }

    /**
     * Section 6.6 step 4, S-33: the chain and the secret of the browser are checked before any key is read or the
     * answer remembered, so that another client spends nothing of either.
     *
     * @throws LogoutRefusedException
     */
    private function answer(Tenant $tenant, ReceivedLogoutResponse $received, ?LogoutChainSecret $secret): SignOutAnswer
    {
        $requestId = $received->response->inResponseTo ?? throw self::unawaited();
        $chain = $this->chains->awaiting($tenant, $requestId);
        if ($chain === null || ! $chain->isOpen($this->clock->now()) || $secret === null || ! $chain->isHeldBy($secret)) {
            throw self::unawaited();
        }
        try {
            $serviceProvider = $this->serviceProviders->read($tenant, $chain->progress->awaitingFrom);
        } catch (MetadataRefusedException $exception) {
            throw new LogoutRefusedException($exception->getMessage(), 0, $exception);
        }
        $endpoints = $this->endpoints->locate($tenant);
        try {
            $accepted = $received->validate(
                new LogoutResponseValidator($this->loader, $this->clock, new TenantReplayGuard($this->replay, $tenant)),
                $serviceProvider->read->role,
                ModelIdentityProvider::of($endpoints, [], false),
                $endpoints->singleLogout,
                $requestId,
            );
        } catch (RefusedXml $exception) {
            throw new LogoutRefusedException($exception->getMessage(), 0, $exception);
        }

        return new SignOutAnswer($chain, $accepted->response->status->code === StatusCode::Success, $secret);
    }

    private static function unawaited(): LogoutRefusedException
    {
        return new LogoutRefusedException('The LogoutResponse answers no request an open chain of logout waits for (spec/saml.md S-33).');
    }

    /**
     * Section 6.5 step 1 in order.
     *
     * @throws LogoutRefusedException
     */
    private function request(Tenant $tenant, ReceivedLogoutRequest $received): SignOutRequest
    {
        try {
            $serviceProvider = $this->serviceProviders->read($tenant, $received->request->issuer);
        } catch (MetadataRefusedException $exception) {
            throw new LogoutRefusedException($exception->getMessage(), 0, $exception);
        }
        $role = $serviceProvider->read->role;
        $answer = self::answerEndpoint($role, $received->binding);
        $endpoints = $this->endpoints->locate($tenant);
        try {
            $accepted = $received->validate(
                new LogoutRequestValidator($this->loader, $this->clock, new TenantReplayGuard($this->replay, $tenant)),
                $role,
                ModelIdentityProvider::of($endpoints, [], false),
                $endpoints->singleLogout,
            );
        } catch (RefusedXml $exception) {
            throw new LogoutRefusedException($exception->getMessage(), 0, $exception);
        }
        $request = $accepted->request;
        $nameId = $request->nameId;

        return new SignOutRequest(
            $serviceProvider->declaration->entityId,
            $request->id,
            $nameId->value,
            $nameId->format->value,
            $nameId->nameQualifier,
            $nameId->spNameQualifier,
            $request->sessionIndexes,
            $received->relayState,
            $answer->binding->value,
            $answer->responseLocation ?? $answer->location,
        );
    }

    /**
     * S-27, M-9
     *
     * @throws LogoutRefusedException
     */
    private static function answerEndpoint(ServiceProvider $role, Binding $binding): Endpoint
    {
        foreach ($role->singleLogoutServices as $endpoint) {
            if ($endpoint->binding === $binding) {
                return $endpoint;
            }
        }

        return (
            $role->singleLogoutServices[0] ?? throw new LogoutRefusedException('The metadata of the service provider list no single logout service the answer could go to (spec/saml.md S-27).')
        );
    }
}
