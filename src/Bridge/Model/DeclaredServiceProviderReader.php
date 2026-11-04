<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Port\ServiceProvidersInterface;

/**
 * spec/saml.md section 6.3 step 1, section 6.5 step 1
 *
 * The accepted document is read back with readTrusted(), the channel being its own sealed store.
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
     * @param string|null $issuer the unverified Issuer of the message
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
