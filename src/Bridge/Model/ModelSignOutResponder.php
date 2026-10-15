<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Domain\SingleLogout\SignOutResponse;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use Beffroi\Saml\Port\SignOutResponderInterface;
use Beffroi\Saml2\Bindings\PostSender;
use Beffroi\Saml2\Bindings\RedirectSender;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Protocol\LogoutResponse;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Xml\Core\Exception\RefusedXml;
use InvalidArgumentException;

/**
 * The answer to a LogoutRequest written with saml2-model's objects and sent through saml2-bindings (spec/saml.md
 * section 6.5 step 4, S-27): a LogoutResponse of a new ID to the single logout service resolved when the request was
 * received, its InResponseTo the ID of the request, its Issuer the entity ID of the tenant, its Status the one of S-24;
 * signed by the active SAML key of the tenant under RSA-SHA256 (TenantSigning), over the query string by RedirectSender
 * for HTTP-Redirect, in its XML by PostSender for HTTP-POST; the RelayState received handed back as it is.
 */
final readonly class ModelSignOutResponder implements SignOutResponderInterface
{
    public function __construct(
        private TenantSigning $signing,
        private RedirectSender $redirect = new RedirectSender(),
        private PostSender $post = new PostSender(),
    ) {
    }

    public function answer(Tenant $tenant, SignOutResponse $response): PostedForm|RedirectedMessage
    {
        $request = $response->request;
        $status = $response->status;
        $secondLevel = $status->secondLevel();
        $message = new LogoutResponse(
            SamlId::generate(),
            $response->issuedAt,
            new Issuer($response->identityProvider),
            $request->answerLocation,
            $request->id,
            new Status(
                StatusCode::fromUri($status->topLevel()),
                $secondLevel === null ? null : SecondLevelStatusCode::tryFromUri($secondLevel),
            ),
        );
        try {
            $signing = $this->signing->of($tenant);
            if (Binding::from($request->answerBinding) === Binding::HttpRedirect) {
                return new RedirectedMessage($this->redirect->logoutResponse($message, $signing, $request->relayState));
            }
            $form = $this->post->logoutResponse($message, $signing, $request->relayState);
        } catch (RefusedXml|InvalidArgumentException $exception) {
            throw new RuntimeException('The answer of single logout is one its own reader refuses (spec/saml.md section 6.5 step 4).', 0, $exception);
        }

        return new PostedForm($form->action, $form->fields);
    }
}
