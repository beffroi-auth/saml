<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleSignOn;

/**
 * The values are as they go on the wire, not escaped for HTML: the page of the application escapes them.
 */
final readonly class PostedForm
{
    /**
     * @param array<string, string> $fields
     * @param list<string> $reaches the URLs a redirection of the submission may go through after the action
     */
    public function __construct(
        public string $action,
        public array $fields,
        public array $reaches = [],
    ) {
    }
}
