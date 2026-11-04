<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Domain\SingleLogout\SignOutResponse;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;

interface SignOutResponderInterface
{
    /**
     * Called before anything of the request is read, so that a key that cannot be opened ends nothing and remembers
     * nothing (S-23, S-27).
     *
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     */
    public function open(Tenant $tenant): void;

    /**
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     */
    public function answer(Tenant $tenant, SignOutResponse $response): PostedForm|RedirectedMessage;
}
