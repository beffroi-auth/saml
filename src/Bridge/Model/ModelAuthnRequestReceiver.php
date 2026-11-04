<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\ServiceProvider\AuthnRequestSigning;
use Beffroi\Saml\Domain\SingleSignOn\SignOnRequest;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Exception\SignOnRefusedException;
use Beffroi\Saml\Port\AuthnRequestReceiverInterface;
use Beffroi\Saml\Port\IdentityProviderEndpointsInterface;
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\ReceivedAuthnRequest;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Model\Protocol\RequestedAuthnContext;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Psr\Clock\ClockInterface;

/**
 * spec/saml.md section 6.3, section 6.4 step 1, section 6.8, S-9, M-14, M-16, B-11
 */
final readonly class ModelAuthnRequestReceiver implements AuthnRequestReceiverInterface
{
    private RedirectReceiver $redirect;

    private PostReceiver $post;

    private AuthnRequestValidator $validator;

    public function __construct(
        private DeclaredServiceProviderReader $serviceProviders,
        private IdentityProviderEndpointsInterface $endpoints,
        private ClockInterface $clock,
    ) {
        $loader = SamlLoader::create();
        $this->redirect = new RedirectReceiver($loader);
        $this->post = new PostReceiver($loader);
        $this->validator = new AuthnRequestValidator($loader, $clock);
    }

    public function redirect(Tenant $tenant, string $queryString): SignOnRequest
    {
        try {
            $received = $this->redirect->authnRequest($queryString);
        } catch (RefusedXml $exception) {
            throw new SignOnRefusedException($exception->getMessage(), 0, $exception);
        }

        return $this->validated($tenant, $received);
    }

    public function post(Tenant $tenant, array $fields): SignOnRequest
    {
        try {
            $received = $this->post->authnRequest($fields);
        } catch (RefusedXml $exception) {
            throw new SignOnRefusedException($exception->getMessage(), 0, $exception);
        }

        return $this->validated($tenant, $received);
    }

    /**
     * Section 6.3, in order
     *
     * @throws SignOnRefusedException
     */
    private function validated(Tenant $tenant, ReceivedAuthnRequest $received): SignOnRequest
    {
        try {
            $serviceProvider = $this->serviceProviders->read($tenant, $received->request->issuer);
        } catch (MetadataRefusedException $exception) {
            throw new SignOnRefusedException($exception->getMessage(), 0, $exception);
        }
        $declaration = $serviceProvider->declaration;
        $read = $serviceProvider->read;
        $endpoints = $this->endpoints->locate($tenant);
        $parties = new ModelAuthnRequestParties(
            AuthnRequestSigning::of($declaration, $read->metadata),
            $read->role,
            ModelIdentityProvider::of($endpoints, [], false),
        );
        try {
            $validated = $received->validate($this->validator, $parties->serviceProvider, $parties->identityProvider, $endpoints->singleSignOn);
        } catch (RefusedXml $exception) {
            throw new SignOnRefusedException($exception->getMessage(), 0, $exception);
        }
        $request = $validated->request;

        return new SignOnRequest(
            $declaration->entityId,
            $request->id,
            $validated->assertionConsumerService->location,
            $received->relayState,
            $request->forceAuthn,
            $request->isPassive,
            $request->nameIdPolicy?->format,
            $request->requestedAuthnContext instanceof RequestedAuthnContext,
            $this->clock->now(),
        );
    }
}
