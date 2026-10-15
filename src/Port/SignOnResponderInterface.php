<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use Beffroi\Saml\Domain\SingleSignOn\SignOnFailure;
use Beffroi\Saml\Domain\SingleSignOn\SignOnResponse;

/**
 * The answer to a request, written, signed by the active SAML key of the tenant and turned into the form of HTTP-POST
 * (spec/saml.md section 6.4 step 7, S-14, S-15).
 */
interface SignOnResponderInterface
{
    /**
     * @throws KeyNotFoundException when the tenant holds no active SAML key
     * @throws KmsUnavailableException when the KMS does not answer to open it
     */
    public function success(Tenant $tenant, SignOnResponse $response): PostedForm;

    /**
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     */
    public function failure(Tenant $tenant, SignOnFailure $failure): PostedForm;
}
