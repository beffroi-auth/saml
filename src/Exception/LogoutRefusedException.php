<?php

declare(strict_types=1);

namespace Beffroi\Saml\Exception;

use RuntimeException;

/**
 * A logout message single logout does not answer (spec/saml.md S-22, S-23, section 6.5 step 1): refused
 * before its answer is established, by the binding, the model, the replay store or the declaration of its service
 * provider. It ends no session and gets no SAML answer, the page of a refusal instead; the message names the rule and
 * never a value of the message (M-16, B-11), so that it is shown and written to a log as it is.
 */
final class LogoutRefusedException extends RuntimeException implements ExceptionInterface
{
}
