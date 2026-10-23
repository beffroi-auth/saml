<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\Upstream\UpstreamIdentityProvider;
use Beffroi\Saml\Domain\Upstream\VerifiedAssertion;
use Beffroi\Saml\Exception\AssertionRefusedException;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Exception\UpstreamAuthenticationFailedException;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Port\ReplayStoreInterface;
use Beffroi\Saml\Port\ResponseReceiverInterface;
use Beffroi\Saml\Port\ServiceProviderEndpointsInterface;
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\UnsuccessfulResponse;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Psr\Clock\ClockInterface;

/**
 * The response an upstream identity provider posted, read by saml2-bindings' PostReceiver and validated by
 * saml2-model's ResponseValidator (spec/saml.md S-53, section 6.14 step 3, model.md section 6.1): under the accepted
 * document of the provider the request went to, read back from the table of its role with readTrusted() and held to
 * S-42 and S-43 again (ModelUpstreamMetadataReader::readAccepted()), never under a provider the message names; with the
 * key of that provider, opened before anything of the response is read (S-66, section 6.13); as the answer to the
 * request of that ID, received at the assertion consumer service of the tenant for its entity ID
 * (ExpectedResponse::toRequest()), the assertion remembered under its issuer and its ID by the replay store of S-23 for
 * that tenant (TenantReplayGuard). What the binding, the model, Dsig and Enc refuse is one refusal, its message theirs,
 * which names the rule and never a value (M-16).
 */
final readonly class ModelResponseReceiver implements ResponseReceiverInterface
{
    /**
     * @param AcceptedMetadataRepositoryInterface $accepted the accepted documents of the upstream identity providers,
     *                                                      the table of their role (S-42)
     */
    public function __construct(
        private AcceptedMetadataRepositoryInterface $accepted,
        private ModelUpstreamMetadataReader $reader,
        private UpstreamDecryptionKeys $keys,
        private ServiceProviderEndpointsInterface $endpoints,
        private ReplayStoreInterface $store,
        private ClockInterface $clock,
    ) {
    }

    public function receive(Tenant $tenant, UpstreamIdentityProvider $provider, array $fields, string $requestId): VerifiedAssertion
    {
        $document = $this->accepted->find($tenant, $provider->entityId);
        if ($document === null) {
            throw new AssertionRefusedException('The identity provider has no metadata accepted (spec/saml.md S-53).');
        }
        try {
            $identityProvider = $this->reader->readAccepted($document->document);
        } catch (MetadataRefusedException $exception) {
            throw new AssertionRefusedException($exception->getMessage(), 0, $exception);
        }
        // S-66: the keys of the provider opened before the response is read, so that a KMS that does not answer refuses
        // it before anything of it is decrypted
        $key = $this->keys->of($tenant, $provider->entityId);
        if ($key !== null) {
            $identityProvider = $identityProvider->withDecryptionKey($key);
        }
        $endpoints = $this->endpoints->locate($tenant);
        $loader = SamlLoader::create();
        try {
            $accepted = new PostReceiver($loader)
                ->response($fields)
                ->validate(
                    new ResponseValidator($loader, $this->clock, new TenantReplayGuard($this->store, $tenant)),
                    $identityProvider,
                    ExpectedResponse::toRequest($requestId, $endpoints->assertionConsumerService, $endpoints->entityId),
                );
        } catch (UnsuccessfulResponse $failure) {
            // S-58: held to the request it answers before the model says it failed; nothing of it travels on
            throw new UpstreamAuthenticationFailedException($failure->status->secondLevel === SecondLevelStatusCode::NoPassive);
        } catch (RefusedXml $exception) {
            throw new AssertionRefusedException($exception->getMessage(), 0, $exception);
        }
        $assertion = $accepted->assertion;
        $attributes = [];
        foreach ($assertion->attributes as $attribute) {
            // an attribute named twice is one attribute of the person, its values in document order (model.md
            // section 6.1 step 11, merging them being the consumer's)
            $attributes[$attribute->name] = [...($attributes[$attribute->name] ?? []), ...$attribute->values];
        }

        return new VerifiedAssertion(
            $assertion->nameId->value,
            $assertion->nameId->format === NameIdFormat::Persistent,
            $attributes,
            $assertion->authnStatement->authnInstant,
            $assertion->authnStatement->authnContextClassRef,
            $accepted->encrypted,
            $assertion->authnStatement->sessionNotOnOrAfter,
        );
    }
}
