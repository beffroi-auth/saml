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
 * spec/saml.md section 6.5 step 4, S-27
 */
final readonly class ModelSignOutResponder implements SignOutResponderInterface
{
    public function __construct(
        private TenantSigning $signing,
        private RedirectSender $redirect = new RedirectSender(),
        private PostSender $post = new PostSender(),
    ) {
    }

    public function open(Tenant $tenant): void
    {
        try {
            $this->signing->of($tenant);
        } catch (RefusedXml|InvalidArgumentException $exception) {
            throw new RuntimeException('The active SAML key of the tenant is one Dsig refuses to sign with (spec/saml.md section 6.5 step 1).', 0, $exception);
        }
    }

    public function answer(Tenant $tenant, SignOutResponse $response): PostedForm|RedirectedMessage
    {
        $requester = $response->requester;
        $status = $response->status;
        $secondLevel = $status->secondLevel();
        $message = new LogoutResponse(
            SamlId::generate(),
            $response->issuedAt,
            new Issuer($response->identityProvider),
            $requester->answerLocation,
            $requester->requestId,
            new Status(
                StatusCode::fromUri($status->topLevel()),
                $secondLevel === null ? null : SecondLevelStatusCode::tryFromUri($secondLevel),
            ),
        );
        try {
            $signing = $this->signing->of($tenant);
            if (Binding::from($requester->answerBinding) === Binding::HttpRedirect) {
                return new RedirectedMessage($this->redirect->logoutResponse($message, $signing, $requester->relayState));
            }
            $form = $this->post->logoutResponse($message, $signing, $requester->relayState);
        } catch (RefusedXml|InvalidArgumentException $exception) {
            throw new RuntimeException('The answer of single logout is one its own reader refuses (spec/saml.md section 6.5 step 4).', 0, $exception);
        }

        return new PostedForm($form->action, $form->fields);
    }
}
