<?php

declare(strict_types=1);

namespace Beffroi\Saml\Exception;

use RuntimeException;

/**
 * The metadata of a service provider refused, or out of reach (spec/saml.md section 6.2): the message names the rule,
 * and never a value of the document (M-16), so that it is written to a log as it is.
 */
final class MetadataRefusedException extends RuntimeException implements ExceptionInterface
{
}
