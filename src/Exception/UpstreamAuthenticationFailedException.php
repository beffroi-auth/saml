<?php

declare(strict_types=1);

namespace Beffroi\Saml\Exception;

use RuntimeException;

/**
 * spec/saml.md S-58. It says whether the status is NoPassive and nothing else: neither the StatusMessage nor any code
 * of the response reaches the client or the page.
 */
final class UpstreamAuthenticationFailedException extends RuntimeException implements ExceptionInterface
{
    public function __construct(
        public readonly bool $noPassive,
    ) {
        parent::__construct('The identity provider authenticated nobody (spec/saml.md S-58).');
    }
}
