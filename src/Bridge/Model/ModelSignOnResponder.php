<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use function array_map;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Port\KeptSigningKeyProviderInterface;
use Beffroi\Saml\Bridge\Pki\RsaPrivateKey;
use Beffroi\Saml\Domain\Key\SamlSigningAlgorithmInterface;
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
use Beffroi\Saml2\Model\Writing\SignedParts;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Dsig\PrivateKey;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use InvalidArgumentException;

/**
 * The answer to a request written with saml2-model's objects and sent through saml2-bindings' PostSender (spec/saml.md
 * section 6.4 step 7): a Response of a new ID to the assertion consumer service the model resolved, its InResponseTo
 * the ID of the request, its Issuer the entity ID of the tenant (S-14); its one assertion of a new ID, a persistent
 * NameID qualified by both entities (S-13), one bearer confirmation and Conditions ending five minutes after the
 * issue, one AudienceRestriction naming the service provider, an authentication statement of the session, the
 * unspecified class, and the attributes released (S-16); the assertion signed, then the response over it, under
 * RSA-SHA256, by the active SAML key of the tenant (S-15); the RelayState received handed back as it is.
 *
 * The key is the core's, opened by the KMS once per process (KeptSigningKeyProviderInterface), turned into a key of
 * OpenSSL in memory for the call and dropped with it (S-1).
 */
final readonly class ModelSignOnResponder implements SignOnResponderInterface
{
    /**
     * Authentication Context §3.4.27: the class that says nothing the identity provider has not mapped (section 12).
     */
    public const string CONTEXT_CLASS = 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified';

    public function __construct(
        private KeptSigningKeyProviderInterface $keys,
        private SamlSigningAlgorithmInterface $algorithm,
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
                        new Conditions(null, $notOnOrAfter, [[$request->serviceProvider]], false),
                        new AuthnStatement($response->authnInstant, $response->sessionIndex, null, self::CONTEXT_CLASS),
                        array_map(self::attribute(...), $response->attributes),
                    ),
                ),
                $this->signing($tenant),
                SignedParts::AssertionAndResponse,
                $request->relayState,
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
                $this->signing($tenant),
                $request->relayState,
            ));
        } catch (RefusedXml|InvalidArgumentException $exception) {
            throw new RuntimeException('The failure of single sign-on is one its own reader refuses (spec/saml.md section 6.4 step 7).', 0, $exception);
        }
    }

    /**
     * The active SAML key of the tenant as Dsig signs with it, under RSA-SHA256 (S-15).
     */
    private function signing(Tenant $tenant): Signing
    {
        return new Signing(
            PrivateKey::fromPem(RsaPrivateKey::pem($this->keys->activeKeptSigningKey($tenant, $this->algorithm))),
            SignatureAlgorithm::RsaSha256,
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
