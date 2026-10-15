<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\ServiceProvider;

use Beffroi\Core\Exception\InvalidArgumentException;

/**
 * Whether the authentication requests of a service provider need a signature (spec/saml.md S-9, section 6.3 step 2):
 * they do unless its declaration says it does not sign and its accepted metadata do not say it does, the provider's
 * own statement winning towards safety. The setting of the tenant that the metadata of the identity provider announce
 * is not read, nor is any setting of the deployment (decision 0006).
 */
final readonly class AuthnRequestSigning
{
    private function __construct(
        public string $entityId,
        public bool $required,
    ) {
    }

    /**
     * @param ServiceProvider $declaration the service provider as the deployment declares it
     * @param ServiceProviderMetadata $metadata its accepted document, read back
     *
     * @throws InvalidArgumentException when the two are not of one entity ID, a programming error
     */
    public static function of(ServiceProvider $declaration, ServiceProviderMetadata $metadata): self
    {
        if ($declaration->entityId !== $metadata->entityId) {
            throw new InvalidArgumentException('The signature a request needs is read from the declaration and the metadata of one service provider (spec/saml.md section 6.3 step 2).');
        }

        return new self($declaration->entityId, $declaration->signsAuthnRequests || $metadata->authnRequestsSigned);
    }
}
