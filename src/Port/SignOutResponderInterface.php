<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Domain\SingleLogout\SignOutResponse;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;

/**
 * The answer to a LogoutRequest, written, signed by the active SAML key of the tenant and sent over the binding of the
 * single logout service it goes to (spec/saml.md section 6.5 step 4, S-27): the URL of HTTP-Redirect, or the form of
 * HTTP-POST. The key is opened first, before the request is read (section 6.5 step 1).
 */
interface SignOutResponderInterface
{
    /**
     * Opens the active SAML key of the tenant, which the process then holds open for the answer, before anything of the
     * request is read: a key that cannot be opened ends nothing and remembers nothing (S-23, S-27).
     *
     * @throws KeyNotFoundException when the tenant holds no active SAML key
     * @throws KmsUnavailableException when the KMS does not answer to open it
     */
    public function open(Tenant $tenant): void;

    /**
     * @throws KeyNotFoundException when the tenant holds no active SAML key
     * @throws KmsUnavailableException when the KMS does not answer to open it
     */
    public function answer(Tenant $tenant, SignOutResponse $response): PostedForm|RedirectedMessage;
}
