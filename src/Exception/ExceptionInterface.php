<?php

declare(strict_types=1);

namespace Beffroi\Saml\Exception;

use Throwable;

/**
 * Its message names the rule and never a value (M-16), so that it can be shown and logged as it is.
 */
interface ExceptionInterface extends Throwable
{
}
