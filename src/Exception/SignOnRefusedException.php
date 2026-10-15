<?php

declare(strict_types=1);

namespace Beffroi\Saml\Exception;

use RuntimeException;

/**
 * A request single sign-on does not answer (spec/saml.md section 6.4): refused before its endpoint is established,
 * by the binding, the model or the declaration of its service provider, or waiting for a login longer than it may. It
 * gets no SAML answer, the page of a refusal instead; the message names the rule and never a value of the message
 * (M-16, B-11), so that it is shown and written to a log as it is.
 */
final class SignOnRefusedException extends RuntimeException implements ExceptionInterface
{
}
