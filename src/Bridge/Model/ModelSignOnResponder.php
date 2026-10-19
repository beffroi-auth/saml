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
 * The answer to a request written with saml2-model's objects and sent through saml2-bindings' PostSender (spec/saml.md
 * section 6.4 step 7): a Response of a new ID to the assertion consumer service the model resolved, its InResponseTo
 * the ID of the request, its Issuer the entity ID of the tenant (S-14); its one assertion of a new ID, a persistent
 * NameID qualified by both entities (S-13), one bearer confirmation ending five minutes after the issue and Conditions
 * from the issue, their NotBefore, which Entra requires, to five minutes after it, one AudienceRestriction naming the
 * service provider, an authentication statement of the session, the unspecified class, and the attributes released
 * (S-16); the assertion signed, then the response over it, under RSA-SHA256, by the active SAML key of the tenant
 * (S-15); the RelayState received handed back as it is. For a response that names the certificate of a service
 * provider, the assertion encrypted by the model's writer between the two signatures (S-21), for the key of that
 * certificate (S-19), under aes256-gcm and rsa-oaep-mgf1p (S-20).
 *
 * The key is the core's, opened by the KMS once per process, through TenantSigning (S-1).
 */
final readonly class ModelSignOnResponder implements SignOnResponderInterface
{
    /**
     * Authentication Context §3.4.27: the class that says nothing the identity provider has not mapped (section 12).
     */
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
     * S-19, S-20: the key of the certificate the accepted metadata name, under the one scheme, or nothing to encrypt.
     *
     * @throws RefusedXml what Enc refuses of the certificate, which the model's reader already checked (D-16)
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
