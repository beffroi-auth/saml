<?php

declare(strict_types=1);

namespace Beffroi\Saml\Exception;

use RuntimeException;

/**
 * A response of an upstream identity provider the service provider of a tenant does not take (spec/saml.md S-53 to
 * S-56): no request of the browser it answers, a provider no longer declared or with no accepted document, a response
 * the binding, the model, Dsig or Enc refuses, an assertion in clear from a provider asked to encrypt, no subject, no
 * address. Nobody is signed in, the page of a refusal instead; the message names the rule and never a value (M-16), so
 * that it is shown and written to a log as it is.
 */
final class AssertionRefusedException extends RuntimeException implements ExceptionInterface
{
}
