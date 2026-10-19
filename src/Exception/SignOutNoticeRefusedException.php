<?php

declare(strict_types=1);

namespace Beffroi\Saml\Exception;

use RuntimeException;

/**
 * A LogoutRequest the identity provider cannot write for one service provider of a chain (spec/saml.md S-30, S-31):
 * what it is written from refused by the model or by the binding that carries it, a single logout service of the
 * accepted metadata the sender refuses among them. That service provider is passed over and the chain goes on; the
 * message names the rule and never a value, so that it is written to a log as it is.
 */
final class SignOutNoticeRefusedException extends RuntimeException implements ExceptionInterface
{
}
