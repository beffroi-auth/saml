<?php

declare(strict_types=1);

namespace Beffroi\Saml\Exception;

use RuntimeException;

final class UpstreamSignOnRefusedException extends RuntimeException implements ExceptionInterface
{
}
