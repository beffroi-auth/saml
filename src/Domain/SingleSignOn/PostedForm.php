<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleSignOn;

/**
 * The form the browser posts to the assertion consumer service (spec/saml.md section 6.4 step 7, bindings.md section
 * 6.4): where it posts and its fields, SAMLResponse then RelayState when one was received, the values as they go on
 * the wire and not escaped for HTML, which the page of the bundle does (section 6.8).
 */
final readonly class PostedForm
{
    /**
     * @param array<string, string> $fields
     */
    public function __construct(
        public string $action,
        public array $fields,
    ) {
    }
}
