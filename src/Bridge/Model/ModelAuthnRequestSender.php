<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use function array_find;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use Beffroi\Saml\Domain\Upstream\SentAuthnRequest;
use Beffroi\Saml\Domain\Upstream\UpstreamAuthnRequest;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Exception\UpstreamSignOnRefusedException;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Port\AuthnRequestSenderInterface;
use Beffroi\Saml2\Bindings\PostSender;
use Beffroi\Saml2\Bindings\RedirectSender;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Protocol\NameIdPolicy;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Xml\Core\Exception\RefusedXml;
use InvalidArgumentException;

/**
 * spec/saml.md S-48, S-49, S-50, S-68, section 6.11 steps 4 and 5
 */
final readonly class ModelAuthnRequestSender implements AuthnRequestSenderInterface
{
    /**
     * @param AcceptedMetadataRepositoryInterface $accepted the table of the upstream identity providers (S-42)
     */
    public function __construct(
        private AcceptedMetadataRepositoryInterface $accepted,
        private ModelUpstreamMetadataReader $reader,
        private TenantSigning $signing,
        private RedirectSender $redirect = new RedirectSender(),
        private PostSender $post = new PostSender(),
    ) {
    }

    public function send(Tenant $tenant, UpstreamAuthnRequest $request): SentAuthnRequest
    {
        $endpoint = $this->singleSignOnService($tenant, $request->identityProvider);
        // Opened apart from the writing: a key that does not match its public JWK is a fault, not a refusal.
        try {
            $signing = $this->signing->of($tenant);
        } catch (RefusedXml $exception) {
            throw new UpstreamSignOnRefusedException(
                'The request to the identity provider is one the model or the binding refuses to write (spec/saml.md S-48).',
                0,
                $exception,
            );
        }
        try {
            $authnRequest = new AuthnRequest(
                SamlId::generate(),
                $request->issuedAt,
                new Issuer($request->serviceProvider->entityId),
                $endpoint->location,
                $request->serviceProvider->assertionConsumerService,
                protocolBinding: Binding::HttpPost->value,
                nameIdPolicy: new NameIdPolicy(NameIdFormat::Persistent->value, allowCreate: true),
                forceAuthn: $request->forceAuthn,
            );
            if ($endpoint->binding === Binding::HttpRedirect) {
                $message = new RedirectedMessage(self::hinted($this->redirect->authnRequest($authnRequest, $signing, $request->relayState), $request));
            } else {
                $form = $this->post->authnRequest($authnRequest, $signing, $request->relayState);
                $message = new PostedForm(self::hinted($form->action, $request), $form->fields);
            }
        } catch (RefusedXml|InvalidArgumentException $exception) {
            throw new UpstreamSignOnRefusedException(
                'The request to the identity provider is one the model or the binding refuses to write (spec/saml.md S-48).',
                0,
                $exception,
            );
        }

        return new SentAuthnRequest($request, $authnRequest->id, $message);
    }

    public function destination(Tenant $tenant, string $identityProvider): string
    {
        return $this->singleSignOnService($tenant, $identityProvider)->location;
    }

    /**
     * S-68: the hint is appended after whatever the binding signed.
     */
    private static function hinted(string $url, UpstreamAuthnRequest $request): string
    {
        return $request->addressHint?->appendedTo($url) ?? $url;
    }

    /**
     * S-48
     *
     * @throws UpstreamSignOnRefusedException
     */
    private function singleSignOnService(Tenant $tenant, string $identityProvider): Endpoint
    {
        $accepted = $this->accepted->find($tenant, $identityProvider);
        if ($accepted === null) {
            throw new UpstreamSignOnRefusedException('The identity provider has no metadata accepted yet (spec/saml.md S-48).');
        }
        try {
            $services = $this->reader->readAccepted($accepted->document)->singleSignOnServices;
        } catch (MetadataRefusedException $exception) {
            throw new UpstreamSignOnRefusedException($exception->getMessage(), 0, $exception);
        }

        return array_find($services, static fn (Endpoint $service): bool => $service->binding === Binding::HttpRedirect) ?? $services[0];
    }
}
