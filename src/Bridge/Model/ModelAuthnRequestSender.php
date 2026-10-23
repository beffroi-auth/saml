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
 * The AuthnRequest the service provider of a tenant sends an upstream identity provider, written with saml2-model's
 * objects and sent through saml2-bindings (spec/saml.md S-48, section 6.11 steps 4 and 5): the accepted document of the
 * provider read back from the table of its role (ModelUpstreamMetadataReader::readAccepted()), its Destination the
 * Location of the first single sign-on service on HTTP-Redirect of that document, or else of its first one, which the
 * model keeps on HTTP-POST; a new ID, the instant of the request, its Issuer the entity ID of the service provider with
 * no Format, the assertion consumer service of the metadata of the service provider with the binding of HTTP-POST, a
 * persistent NameIDPolicy that allows the provider to create the identifier, ForceAuthn when the request asks for it
 * (S-49); signed by the active SAML key of the tenant under RSA-SHA256 (TenantSigning), opened once the endpoint is
 * known, over the query string by RedirectSender for HTTP-Redirect, in its XML by PostSender for HTTP-POST; the
 * reference of S-50 as its RelayState; the hint of the address, when the request carries one, appended to the URL of
 * HTTP-Redirect after its Signature, outside the octets it covers, and to the action of the form of HTTP-POST (S-68).
 *
 * A provider with no accepted document, one whose document the reading back refuses now, a request the model or the
 * binding refuses to write and a key Dsig refuses to sign with are UpstreamSignOnRefusedException: no request is sent.
 */
final readonly class ModelAuthnRequestSender implements AuthnRequestSenderInterface
{
    /**
     * @param AcceptedMetadataRepositoryInterface $accepted the accepted documents of the upstream identity providers,
     *                                                      the table of their role (S-42)
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
        // the key opened apart from the writing: a key Dsig refuses to sign with is a request refused, and a key whose
        // private half is not the one of its public JWK a fault of the deployment, which goes on as it is
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
     * S-68: the URL the binding wrote, with the hint of the address the request carries when it carries one, after
     * whatever the binding signed.
     */
    private static function hinted(string $url, UpstreamAuthnRequest $request): string
    {
        return $request->addressHint?->appendedTo($url) ?? $url;
    }

    /**
     * S-48: the single sign-on service of the accepted document of the provider, on HTTP-Redirect when the document
     * lists one, whatever their order, and else the first one, which the model keeps on HTTP-POST.
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
