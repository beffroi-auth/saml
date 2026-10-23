<?php

declare(strict_types=1);

namespace Beffroi\Saml\Exception;

use RuntimeException;

/**
 * A response of an upstream identity provider whose status is not Success (spec/saml.md S-58, model.md M-13): the
 * person cancelled at the provider or failed to authenticate there, and the response, held to the request it answers,
 * carries no assertion. What it says of the failure is whether it is NoPassive and nothing else: neither its
 * StatusMessage nor any code of it reaches the client or the page, so the message is the rule's.
 */
final class UpstreamAuthenticationFailedException extends RuntimeException implements ExceptionInterface
{
    public function __construct(
        public readonly bool $noPassive,
    ) {
        parent::__construct('The identity provider authenticated nobody (spec/saml.md S-58).');
    }
}
