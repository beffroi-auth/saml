<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\SingleLogout\SignOutRequest;
use Beffroi\Saml\Exception\LogoutRefusedException;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Port\IdentityProviderEndpointsInterface;
use Beffroi\Saml\Port\LogoutReplayStoreInterface;
use Beffroi\Saml\Port\LogoutRequestReceiverInterface;
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\ReceivedLogoutRequest;
use Beffroi\Saml2\Bindings\ReceivedLogoutResponse;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\LogoutRequestValidator;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;
use Psr\Clock\ClockInterface;

/**
 * A LogoutRequest received over HTTP-Redirect or HTTP-POST and validated by saml2-model (spec/saml.md section 6.5
 * step 1): decoded by the receiver of its binding, its service provider read as single sign-on reads it (section 6.3
 * step 1), the single logout service its answer goes to resolved among those of the accepted metadata (S-27), then the
 * request validated by LogoutRequestValidator, its signature required and verified under the keys of those metadata,
 * its Destination the single logout service of the tenant (S-22), the validator remembering it last in the store of the
 * tenant (S-23). One loader, SamlLoader's, decodes and validates (M-14).
 *
 * What the binding, the model, Core or Dsig refuse, a LogoutResponse, which no request of this identity provider waits
 * for until issue #735, a service provider nobody declared or registered, and one whose metadata list no single logout
 * service, are a LogoutRefusedException carrying the message of the rule, which names no value (M-16, B-11): the answer
 * is not established, so nothing ends and nothing is sent.
 */
final readonly class ModelLogoutRequestReceiver implements LogoutRequestReceiverInterface
{
    private Loader $loader;

    private RedirectReceiver $redirect;

    private PostReceiver $post;

    public function __construct(
        private DeclaredServiceProviderReader $serviceProviders,
        private IdentityProviderEndpointsInterface $endpoints,
        private LogoutReplayStoreInterface $replay,
        private ClockInterface $clock,
    ) {
        $this->loader = SamlLoader::create();
        $this->redirect = new RedirectReceiver($this->loader);
        $this->post = new PostReceiver($this->loader);
    }

    public function redirect(Tenant $tenant, string $queryString): SignOutRequest
    {
        try {
            $received = $this->redirect->logoutMessage($queryString);
        } catch (RefusedXml $exception) {
            throw new LogoutRefusedException($exception->getMessage(), 0, $exception);
        }

        return $this->validated($tenant, $received);
    }

    public function post(Tenant $tenant, array $fields): SignOutRequest
    {
        try {
            $received = $this->post->logoutMessage($fields);
        } catch (RefusedXml $exception) {
            throw new LogoutRefusedException($exception->getMessage(), 0, $exception);
        }

        return $this->validated($tenant, $received);
    }

    /**
     * Section 6.5 step 1 in order.
     *
     * @throws LogoutRefusedException
     */
    private function validated(Tenant $tenant, ReceivedLogoutRequest|ReceivedLogoutResponse $received): SignOutRequest
    {
        if ($received instanceof ReceivedLogoutResponse) {
            throw new LogoutRefusedException('A LogoutResponse answers a request this identity provider has not sent: it sends none before issue #735 (spec/saml.md S-22).');
        }
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
     * S-27, M-9: the single logout service of the accepted metadata the answer goes to, the first on the binding the
     * request arrived over, or else the first listed; none is a refusal.
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
