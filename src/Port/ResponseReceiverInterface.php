<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Saml\Domain\Upstream\UpstreamIdentityProvider;
use Beffroi\Saml\Domain\Upstream\VerifiedAssertion;
use Beffroi\Saml\Exception\AssertionRefusedException;
use Beffroi\Saml\Exception\UpstreamAuthenticationFailedException;

/**
 * The response is validated under the accepted metadata of the provider the request went to, never under one the
 * message names.
 */
interface ResponseReceiverInterface
{
    /**
     * @param array<array-key, mixed> $fields
     *
     * @throws AssertionRefusedException
     * @throws UpstreamAuthenticationFailedException
     * @throws KeyNotFoundException when a key of the provider retired between the reading of the store and its opening
     * @throws KmsUnavailableException
     */
    public function receive(Tenant $tenant, UpstreamIdentityProvider $provider, array $fields, string $requestId): VerifiedAssertion;
}
