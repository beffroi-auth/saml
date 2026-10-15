<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;

/**
 * The secret of a tenant its persistent identifiers are computed with (spec/saml.md S-13): never published, never
 * written to a log, sealed by the KMS of the tenant. Losing it gives every user a new identifier at every service
 * provider.
 */
interface PersistentIdentifierSaltInterface
{
    /**
     * @throws KmsUnavailableException when the KMS of the tenant does not answer to open it
     * @throws RuntimeException when it can neither be read nor drawn
     *
     * @return non-empty-string
     */
    public function saltOf(Tenant $tenant): string;
}
