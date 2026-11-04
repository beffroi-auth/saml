<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\ServiceProvider\AuthnRequestSigning;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;

/**
 * spec/saml.md S-9, S-10, section 6.3 step 3
 *
 * The model refuses an unsigned request when either flag is true, so validate() is never handed the identity
 * provider the metadata publish.
 */
final readonly class ModelAuthnRequestParties
{
    public ServiceProvider $serviceProvider;

    public IdentityProvider $identityProvider;

    /**
     * @throws InvalidArgumentException when the service provider is not the one the requirement was read for
     */
    public function __construct(AuthnRequestSigning $signing, ServiceProvider $serviceProvider, IdentityProvider $identityProvider)
    {
        if ($serviceProvider->entityId !== $signing->entityId) {
            throw new InvalidArgumentException('The signature a request needs applies to the service provider it was read for (spec/saml.md section 6.3 step 3).');
        }
        if ($serviceProvider->authnRequestsSigned && ! $signing->required) {
            throw new InvalidArgumentException('A service provider whose metadata say it signs its requests needs their signature (spec/saml.md S-9).');
        }
        $this->serviceProvider = new ServiceProvider(
            $serviceProvider->entityId,
            $serviceProvider->signingCertificates,
            $serviceProvider->encryptionCertificates,
            $serviceProvider->assertionConsumerServices,
            $serviceProvider->singleLogoutServices,
            $serviceProvider->nameIdFormats,
            $signing->required,
            $serviceProvider->wantAssertionsSigned,
        );
        $this->identityProvider = new IdentityProvider(
            $identityProvider->entityId,
            $identityProvider->signingCertificates,
            $identityProvider->encryptionCertificates,
            $identityProvider->singleSignOnServices,
            $identityProvider->singleLogoutServices,
            $identityProvider->nameIdFormats,
            $signing->required,
        );
    }
}
