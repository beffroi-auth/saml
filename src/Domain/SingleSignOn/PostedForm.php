<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleSignOn;

/**
 * The form the browser posts to the assertion consumer service (spec/saml.md section 6.4 step 7, bindings.md section
 * 6.4): where it posts and its fields, SAMLResponse then RelayState when one was received, the values as they go on
 * the wire and not escaped for HTML, which the page of the bundle does (section 6.8).
 *
 * A form that posts a LogoutRequest of a chain says where a redirection of its submission may go after its action
 * (S-36): the single logout service of the tenant, where its answer comes back, and the services the chain goes on
 * to, which the page names in its "form-action" with the origin of the action. A form that posts a response, which
 * nobody answers, reaches nothing more.
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
