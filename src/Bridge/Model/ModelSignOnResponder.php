<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use function array_map;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\SingleSignOn\AttributeValue;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use Beffroi\Saml\Domain\SingleSignOn\ReleasedAttribute;
use Beffroi\Saml\Domain\SingleSignOn\SignOnFailure;
use Beffroi\Saml\Domain\SingleSignOn\SignOnResponse;
use Beffroi\Saml\Port\SignOnResponderInterface;
use Beffroi\Saml2\Bindings\PostForm;
use Beffroi\Saml2\Bindings\PostSender;
use Beffroi\Saml2\Model\Assertion\Assertion;
use Beffroi\Saml2\Model\Assertion\Attribute;
use Beffroi\Saml2\Model\Assertion\AttributeNameFormat;
use Beffroi\Saml2\Model\Assertion\AuthnStatement;
use Beffroi\Saml2\Model\Assertion\Conditions;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Assertion\SubjectConfirmation;
use Beffroi\Saml2\Model\Protocol\Response;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Saml2\Model\Writing\Encryption;
use Beffroi\Saml2\Model\Writing\SignedParts;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Enc\ContentAlgorithm;
use Beffroi\Xml\Enc\KeyTransport;
use Beffroi\Xml\Enc\PeerKey;
use InvalidArgumentException;

/**
 * spec/saml.md section 6.4 step 7. The Conditions carry a NotBefore, which Entra requires.
 */
final readonly class ModelSignOnResponder implements SignOnResponderInterface
{
    public const string CONTEXT_CLASS = 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified';

    public function __construct(
        private TenantSigning $signing,
        private PostSender $sender = new PostSender(),
    ) {
    }

    public function success(Tenant $tenant, SignOnResponse $response): PostedForm
    {
        $request = $response->request;
        $issuer = new Issuer($response->identityProvider);
        $notOnOrAfter = $response->notOnOrAfter();
        try {
            return self::posted($this->sender->response(
                new Response(
                    SamlId::generate(),
                    $response->issuedAt,
                    $issuer,
                    $request->assertionConsumerService,
                    $request->id,
                    new Status(StatusCode::Success),
                    new Assertion(
                        SamlId::generate(),
                        $response->issuedAt,
                        $issuer,
                        new NameId($response->nameId->value, NameIdFormat::Persistent, $response->identityProvider, $request->serviceProvider),
                        new SubjectConfirmation($request->assertionConsumerService, $notOnOrAfter, $request->id, null),
                        new Conditions($response->issuedAt, $notOnOrAfter, [[$request->serviceProvider]], false),
                        new AuthnStatement($response->authnInstant, $response->sessionIndex, null, self::CONTEXT_CLASS),
                        array_map(self::attribute(...), $response->attributes),
                    ),
                ),
                $this->signing->of($tenant),
                SignedParts::AssertionAndResponse,
                $request->relayState,
                self::encryption($response->encryptFor),
            ));
        } catch (RefusedXml|InvalidArgumentException $exception) {
            throw new RuntimeException('The response of single sign-on is one its own reader refuses (spec/saml.md section 6.4 step 7).', 0, $exception);
        }
    }

    public function failure(Tenant $tenant, SignOnFailure $failure): PostedForm
    {
        $request = $failure->request;
        try {
            return self::posted($this->sender->failure(
                new Response(
                    SamlId::generate(),
                    $failure->issuedAt,
                    new Issuer($failure->identityProvider),
                    $request->assertionConsumerService,
                    $request->id,
                    new Status(StatusCode::fromUri($failure->status->topLevel()), SecondLevelStatusCode::tryFromUri($failure->status->value)),
                    null,
                ),
                $this->signing->of($tenant),
                $request->relayState,
            ));
        } catch (RefusedXml|InvalidArgumentException $exception) {
            throw new RuntimeException('The failure of single sign-on is one its own reader refuses (spec/saml.md section 6.4 step 7).', 0, $exception);
        }
    }

    /**
     * S-19, S-20
     *
     * @throws RefusedXml
     */
    private static function encryption(?Certificate $certificate): ?Encryption
    {
        if (! $certificate instanceof Certificate) {
            return null;
        }

        return new Encryption(
            PeerKey::fromCertificateBase64($certificate->base64),
            ContentAlgorithm::Aes256Gcm,
            KeyTransport::mgf1p(),
        );
    }

    private static function attribute(ReleasedAttribute $attribute): Attribute
    {
        return new Attribute(
            $attribute->name,
            AttributeNameFormat::from($attribute->nameFormat->value),
            $attribute->friendlyName,
            array_map(static fn (AttributeValue $value): string => $value->value, $attribute->values),
        );
    }

    private static function posted(PostForm $form): PostedForm
    {
        return new PostedForm($form->action, $form->fields);
    }
}
