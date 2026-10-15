<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\ServiceProvider\AuthnRequestSigning;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;

/**
 * The signature an authentication request needs, in saml2-model's terms (spec/saml.md S-9, section 6.3 step 3): the
 * service provider read from its accepted document and the identity provider of the tenant, each rebuilt with its flag
 * set to the requirement, every other value as it was. The model refuses an unsigned request when either flag is true
 * (model.md section 6.2 step 2), so the identity provider the metadata publish, which carries the setting of the
 * tenant, is never the one validate() is handed; the assertion consumer services stay those of the document (S-10).
 */
final readonly class ModelAuthnRequestParties
{
    /**
     * The service provider validate() is handed, its authnRequestsSigned the requirement.
     */
    public ServiceProvider $serviceProvider;

    /**
     * Our own role as validate() is handed it, its wantAuthnRequestsSigned the requirement.
     */
    public IdentityProvider $identityProvider;

    /**
     * @param ServiceProvider $serviceProvider the service provider read from its accepted document
     * @param IdentityProvider $identityProvider the identity provider of the tenant
     *
     * @throws InvalidArgumentException when the service provider is not the one the requirement was read for, of
     *                                  another entity or signing where the requirement says none, a programming error
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
