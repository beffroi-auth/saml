<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Saml\Domain\SingleLogout\SentSignOutNotice;
use Beffroi\Saml\Domain\SingleLogout\SignOutNotice;
use Beffroi\Saml\Exception\SignOutNoticeRefusedException;

interface SignOutNotifierInterface
{
    public function destination(Tenant $tenant, string $serviceProvider): ?string;

    /**
     * Null exactly when destination() is.
     *
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     * @throws SignOutNoticeRefusedException
     */
    public function notify(Tenant $tenant, SignOutNotice $notice): ?SentSignOutNotice;
}
