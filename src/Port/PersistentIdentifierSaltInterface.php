<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;

/**
 * Never published nor written to a log, sealed by the KMS of the tenant: losing it gives every user a new identifier
 * at every service provider.
 */
interface PersistentIdentifierSaltInterface
{
    /**
     * @throws KmsUnavailableException
     * @throws RuntimeException when it can neither be read nor drawn
     *
     * @return non-empty-string
     */
    public function saltOf(Tenant $tenant): string;
}
