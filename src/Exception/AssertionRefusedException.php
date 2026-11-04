<?php

declare(strict_types=1);

namespace Beffroi\Saml\Exception;

use RuntimeException;

final class AssertionRefusedException extends RuntimeException implements ExceptionInterface
{
}
