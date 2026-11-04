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
 * spec/saml.md S-53, section 6.14 step 3
 */
final readonly class ModelResponseReceiver implements ResponseReceiverInterface
{
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
        // S-66: opened before the response is read, so that a KMS that does not answer refuses it first.
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
            throw new UpstreamAuthenticationFailedException($failure->status->secondLevel === SecondLevelStatusCode::NoPassive);
        } catch (RefusedXml $exception) {
            throw new AssertionRefusedException($exception->getMessage(), 0, $exception);
        }
        $assertion = $accepted->assertion;
        $attributes = [];
        foreach ($assertion->attributes as $attribute) {
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
