<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Saml\Domain\Upstream\UpstreamIdentityProvider;
use Beffroi\Saml\Domain\Upstream\VerifiedAssertion;
use Beffroi\Saml\Exception\AssertionRefusedException;

/**
 * The response an upstream identity provider posted to the assertion consumer service of a tenant (spec/saml.md S-53,
 * section 6.14 step 3): read from the fields of the form, validated under the accepted metadata of that provider and
 * never under a provider the message names, with the key of that provider to open an assertion it encrypted (S-66),
 * as the answer to the request of that ID, its assertion remembered by the replay store of S-23.
 */
interface ResponseReceiverInterface
{
    /**
     * @param UpstreamIdentityProvider $provider the declaration of the provider the request went to
     * @param array<array-key, mixed> $fields the fields of the form, as the bundle received them (bindings.md 6.8)
     * @param string $requestId the ID of the request the response answers (M-10)
     *
     * @throws AssertionRefusedException when the provider has no accepted document, or the reading back, the binding,
     *                                   the model, Dsig or Enc refuses, the message naming the rule and never a value
     * @throws KeyNotFoundException when a key of the provider retired between the reading of the store and its opening
     * @throws KmsUnavailableException when the KMS does not answer to open a key of the provider
     */
    public function receive(Tenant $tenant, UpstreamIdentityProvider $provider, array $fields, string $requestId): VerifiedAssertion;
}
