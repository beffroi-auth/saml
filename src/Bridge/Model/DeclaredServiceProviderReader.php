<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Port\ServiceProvidersInterface;

/**
 * The service provider the unverified Issuer of a message names, which single sign-on and single logout read the same
 * way (spec/saml.md section 6.3 step 1, section 6.5 step 1): its declaration among those of the tenant, and its accepted
 * document, read back once with readTrusted(), the channel being its own sealed store. No declaration, no accepted
 * document, or a document the reading refuses now, is a MetadataRefusedException naming the rule, which the receiver
 * of each message turns into its own refusal: the endpoint of the message is not established, so it gets no SAML
 * answer.
 */
final readonly class DeclaredServiceProviderReader
{
    public function __construct(
        private ServiceProvidersInterface $serviceProviders,
        private AcceptedMetadataRepositoryInterface $accepted,
        private ModelServiceProviderMetadataReader $reader,
    ) {
    }

    /**
     * @param string|null $issuer the unverified Issuer of the message, null when it carries none
     *
     * @throws MetadataRefusedException
     */
    public function read(Tenant $tenant, ?string $issuer): DeclaredServiceProvider
    {
        $declaration = $issuer === null ? null : $this->serviceProviders->find($tenant, $issuer);
        if ($declaration === null) {
            throw new MetadataRefusedException('The Issuer of the request is no service provider this tenant declares (spec/saml.md section 6.3 step 1).');
        }
        $accepted = $this->accepted->find($tenant, $declaration->entityId);
        if ($accepted === null) {
            throw new MetadataRefusedException('The service provider of the request has no metadata accepted yet (spec/saml.md section 6.3 step 1).');
        }

        return new DeclaredServiceProvider($declaration, $this->reader->readAccepted($accepted->document));
    }
}
