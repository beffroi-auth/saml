<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;

/**
 * The store the assertions of the upstream identity providers and the logout messages the model accepted are
 * remembered in alike (spec/saml.md S-23, S-53, model.md M-11), the bundle's: shared by every worker of the
 * deployment, and atomic, two concurrent calls with the same message answering true
 * once, since a store that checks then writes lets two workers accept the same message.
 */
interface ReplayStoreInterface
{
    /**
     * @param string $issuer the verified entity ID of the issuer of the message
     * @param string $id the verified ID of the message
     * @param DateTimeImmutable $expiresAt when it may be forgotten, the end of the window in which the model would
     *                                     accept it again
     *
     * @return bool true when the message had not been seen under $tenant and is now remembered, false when it had
     */
    public function remember(Tenant $tenant, string $issuer, string $id, DateTimeImmutable $expiresAt): bool;
}
