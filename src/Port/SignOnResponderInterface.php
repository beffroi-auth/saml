<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use Beffroi\Saml\Domain\SingleSignOn\SignOnFailure;
use Beffroi\Saml\Domain\SingleSignOn\SignOnResponse;

interface SignOnResponderInterface
{
    /**
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     */
    public function success(Tenant $tenant, SignOnResponse $response): PostedForm;

    /**
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     */
    public function failure(Tenant $tenant, SignOnFailure $failure): PostedForm;
}
