<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Domain\SingleLogout\SentSignOutNotice;
use Beffroi\Saml\Domain\SingleLogout\SignOutNotice;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Exception\SignOutNoticeRefusedException;
use Beffroi\Saml\Port\SignOutNotifierInterface;
use Beffroi\Saml2\Bindings\PostSender;
use Beffroi\Saml2\Bindings\RedirectSender;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Protocol\LogoutRequest;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Xml\Core\Exception\RefusedXml;
use InvalidArgumentException;

/**
 * The LogoutRequest the identity provider sends a service provider of an ended session, written with saml2-model's
 * objects and sent through saml2-bindings (spec/saml.md S-31, section 6.6 step 3): its service provider read back as
 * single sign-on reads it (section 6.3 step 1), its Destination the Location of the first SingleLogoutService of the
 * accepted document, which the model keeps on HTTP-Redirect or HTTP-POST only; a new ID, its Issuer the entity ID of
 * the tenant, its NotOnOrAfter 300 seconds on, its persistent NameID qualified by the two entities as the assertion
 * carried it (S-14), the ID of the session as its one SessionIndex; signed by the active SAML key of the tenant under
 * RSA-SHA256 (TenantSigning), over the query string by RedirectSender for HTTP-Redirect, in its XML by PostSender for
 * HTTP-POST; no RelayState.
 *
 * A service provider nobody declares any more, one with no accepted document or one the reading refuses now, and one
 * whose metadata list no single logout service, cannot be told: null (S-30). A request the model or the binding
 * refuses to write, a single logout service the sender refuses or a key Dsig refuses to sign with, is
 * SignOutNoticeRefusedException, which passes that service provider over.
 */
final readonly class ModelSignOutNotifier implements SignOutNotifierInterface
{
    public function __construct(
        private DeclaredServiceProviderReader $serviceProviders,
        private TenantSigning $signing,
        private RedirectSender $redirect = new RedirectSender(),
        private PostSender $post = new PostSender(),
    ) {
    }

    public function destination(Tenant $tenant, string $serviceProvider): ?string
    {
        return $this->endpoint($tenant, $serviceProvider)?->location;
    }

    public function notify(Tenant $tenant, SignOutNotice $notice): ?SentSignOutNotice
    {
        $endpoint = $this->endpoint($tenant, $notice->serviceProvider);
        if ($endpoint === null) {
            return null;
        }
        try {
            $request = new LogoutRequest(
                SamlId::generate(),
                $notice->issuedAt,
                new Issuer($notice->identityProvider),
                $endpoint->location,
                $notice->notOnOrAfter(),
                new NameId($notice->nameId, NameIdFormat::Persistent, $notice->identityProvider, $notice->serviceProvider),
                [$notice->sessionIndex],
            );
            $signing = $this->signing->of($tenant);
            if ($endpoint->binding === Binding::HttpRedirect) {
                return new SentSignOutNotice($request->id, new RedirectedMessage($this->redirect->logoutRequest($request, $signing)));
            }
            $form = $this->post->logoutRequest($request, $signing);
        } catch (RefusedXml|InvalidArgumentException $exception) {
            throw new SignOutNoticeRefusedException(
                'The logout request of the identity provider is one its own reader refuses (spec/saml.md S-31).',
                0,
                $exception,
            );
        }

        return new SentSignOutNotice($request->id, new PostedForm($form->action, $form->fields));
    }

    /**
     * S-30, S-31: the first single logout service of the accepted document, or null when there is none to tell.
     */
    private function endpoint(Tenant $tenant, string $serviceProvider): ?Endpoint
    {
        try {
            $read = $this->serviceProviders->read($tenant, $serviceProvider);
        } catch (MetadataRefusedException) {
            return null;
        }

        return $read->read->role->singleLogoutServices[0] ?? null;
    }
}
