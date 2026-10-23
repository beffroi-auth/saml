<?php

declare(strict_types=1);

namespace Beffroi\Saml\Exception;

use RuntimeException;

/**
 * A sign-on the service provider of a tenant cannot start at an upstream identity provider (spec/saml.md S-48): a
 * provider the tenant does not declare, one with no accepted document, a document its reading back refuses now, or a
 * request the model, the binding or Dsig refuses to write. No request is sent, the page of a refusal instead; the
 * message names the rule and never a value (M-16), so that it is shown and written to a log as it is.
 */
final class UpstreamSignOnRefusedException extends RuntimeException implements ExceptionInterface
{
}
