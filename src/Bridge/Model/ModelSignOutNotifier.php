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
 * spec/saml.md S-31, section 6.6 step 3
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
