<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Saml\Domain\SingleLogout\SentSignOutNotice;
use Beffroi\Saml\Domain\SingleLogout\SignOutNotice;

/**
 * The LogoutRequest the identity provider sends a service provider of an ended session (spec/saml.md S-30, S-31),
 * written to the first single logout service of its accepted metadata, read back when it is written, and signed by the
 * active SAML key of the tenant.
 */
interface SignOutNotifierInterface
{
    /**
     * The URL of the single logout service $serviceProvider would be told at, or null when it cannot be told: no
     * declaration, no accepted document, a document the reading refuses now, no single logout service (S-30).
     */
    public function destination(Tenant $tenant, string $serviceProvider): ?string;

    /**
     * The request written and signed, or null when its service provider cannot be told, as destination() says.
     *
     * @throws KeyNotFoundException when the tenant holds no active SAML key
     * @throws KmsUnavailableException when the KMS does not answer to open it
     */
    public function notify(Tenant $tenant, SignOutNotice $notice): ?SentSignOutNotice;
}
