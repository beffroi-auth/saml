<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\ServiceProvider;

use Beffroi\Core\Exception\InvalidArgumentException;

/**
 * spec/saml.md S-9. The WantAuthnRequestsSigned of the tenant is not read, nor any setting of the deployment
 * (decision 0006).
 */
final readonly class AuthnRequestSigning
{
    private function __construct(
        public string $entityId,
        public bool $required,
    ) {
    }

    /**
     * @throws InvalidArgumentException when the two are not of one entity ID
     */
    public static function of(ServiceProvider $declaration, ServiceProviderMetadata $metadata): self
    {
        if ($declaration->entityId !== $metadata->entityId) {
            throw new InvalidArgumentException('The signature a request needs is read from the declaration and the metadata of one service provider (spec/saml.md section 6.3 step 2).');
        }

        return new self($declaration->entityId, $declaration->signsAuthnRequests || $metadata->authnRequestsSigned);
    }
}
