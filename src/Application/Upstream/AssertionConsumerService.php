<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\Upstream;

use function array_unique;
use function array_values;
use Beffroi\Core\Application\Identity\JustInTimeProvisioning;
use Beffroi\Core\Application\Identity\UpstreamProvisioningRefusedException;
use Beffroi\Core\Domain\Group\GroupMapping;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\UpstreamProvider;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Port\GroupRepositoryInterface;
use Beffroi\Saml\Domain\Upstream\AuthnContextMethods;
use Beffroi\Saml\Domain\Upstream\UpstreamAssertion;
use Beffroi\Saml\Domain\Upstream\UpstreamIdentityProvider;
use Beffroi\Saml\Domain\Upstream\VerifiedAssertion;
use Beffroi\Saml\Exception\AssertionRefusedException;
use Beffroi\Saml\Exception\UpstreamAuthenticationFailedException;
use Beffroi\Saml\Port\ResponseReceiverInterface;
use Beffroi\Saml\Port\UpstreamIdentityProvidersInterface;
use function count;
use function in_array;

/**
 * The assertion consumer service of the service provider of a tenant (spec/saml.md S-53 to S-57, section 6.14 steps 2
 * to 7): the response an upstream identity provider posted, taken as the answer to the request the browser remembers,
 * and what it says of the person, then the person itself, the core's first sign-in. The request remembered, the
 * session, what the client asked and where the browser goes are the bundle's, which holds the HTTP session and the
 * interaction (S-52, S-58, S-59).
 */
final readonly class AssertionConsumerService
{
    public function __construct(
        private UpstreamIdentityProvidersInterface $providers,
        private ResponseReceiverInterface $receiver,
        private GroupRepositoryInterface $groups,
        private JustInTimeProvisioning $provisioning,
    ) {
    }

    /**
     * Section 6.14 steps 2 to 6.
     *
     * @param array<array-key, mixed> $fields the fields of the form the browser posted
     * @param string $identityProvider the entity ID of the provider the remembered request went to
     * @param string $requestId the ID of that request
     *
     * @throws AssertionRefusedException when the response is not taken, naming the rule and never a value (M-16)
     * @throws UpstreamAuthenticationFailedException when the provider authenticated nobody (S-58)
     * @throws KeyNotFoundException when a key of the provider retired between the reading of the store and its opening
     * @throws KmsUnavailableException when the KMS does not answer to open a key of the provider
     */
    public function receive(Tenant $tenant, array $fields, string $identityProvider, string $requestId): UpstreamAssertion
    {
        $provider = $this->providers->find($tenant, $identityProvider);
        if ($provider === null) {
            throw new AssertionRefusedException('The identity provider the request went to is none this tenant declares (spec/saml.md S-53).');
        }
        $verified = $this->receiver->receive($tenant, $provider, $fields, $requestId);
        // S-54: before anything of the assertion is read
        if ($provider->requireEncryptedAssertions && ! $verified->encrypted) {
            throw new AssertionRefusedException('The identity provider is required to encrypt its assertions and sent one in clear (spec/saml.md S-54, S-67).');
        }
        $claims = [];
        $phoneNumber = null;
        $filled = $provider->provider()->claims;
        foreach ($provider->profile as $attribute) {
            $value = self::oneValue($verified, $attribute->name);
            if ($value === null) {
                continue;
            }
            if ($attribute->claim === UpstreamProvider::PHONE_NUMBER) {
                $phoneNumber = $value;
            } elseif (in_array($attribute->claim, $filled, true)) {
                $claims[$attribute->claim] = $value;
            }
        }

        $email = self::address($provider, $verified);

        return new UpstreamAssertion(
            $provider,
            self::subject($provider, $verified, $email),
            $email,
            $claims,
            $phoneNumber,
            $provider->groups === null ? [] : $verified->values($provider->groups->attribute),
            $verified->authenticatedAt,
            AuthnContextMethods::of($verified->contextClass),
            $verified->sessionNotOnOrAfter,
        );
    }

    /**
     * Section 6.14 step 7, S-56: the groups the declaration maps the values to, found in the tenant by their names and
     * never created, then the core's first sign-in, which finds the person by its linked identity, creates it at the
     * first one and writes it, its groups and its telephone number in one unit.
     *
     * @throws UpstreamProvisioningRefusedException when the provider may not create or write that person
     * @throws InvalidArgumentException when a claim is said in a form the profile refuses
     */
    public function personOf(Tenant $tenant, UpstreamAssertion $assertion, RequestContext $context): User
    {
        $declared = $assertion->identityProvider->groups;
        $mapping = null;
        if ($declared !== null) {
            $groups = [];
            foreach (array_values(array_unique($assertion->groups)) as $value) {
                $name = $declared->groupOf($value);
                $group = $name === null ? null : $this->groups->findByName($tenant, $name);
                if ($group !== null) {
                    $groups[$value] = $group;
                }
            }
            $mapping = new GroupMapping($groups);
        }

        return $this->provisioning->personNamedBy(
            $tenant,
            $assertion->identityProvider->provider(),
            $assertion->subject,
            $assertion->email,
            $assertion->claims,
            $context,
            $assertion->phoneNumber,
            $mapping,
            $assertion->groups,
        );
    }

    /**
     * S-55: the value of a persistent NameID, or else the one value of the attribute the declaration names; never the
     * address of the person, whatever names it.
     *
     * @throws AssertionRefusedException
     */
    private static function subject(UpstreamIdentityProvider $provider, VerifiedAssertion $verified, EmailAddress $email): string
    {
        if ($verified->persistent) {
            $subject = $verified->nameId;
        } elseif ($provider->subjectAttribute === null) {
            throw new AssertionRefusedException('The NameID is not persistent and the declaration names no attribute of the subject (spec/saml.md S-55).');
        } else {
            $subject = self::oneValue($verified, $provider->subjectAttribute);
            if ($subject === null || $subject === '') {
                throw new AssertionRefusedException('The attribute of the subject holds not one value (spec/saml.md S-55).');
            }
        }
        if (self::isTheMailboxOf($subject, $email)) {
            throw new AssertionRefusedException('The subject is the address of the person, which is given again to another (spec/saml.md S-55).');
        }

        return $subject;
    }

    /**
     * S-55: whether a subject is the same mailbox as the address, its domain read by the one rule of the domain and its
     * case folded; a subject that is no address is none.
     */
    private static function isTheMailboxOf(string $subject, EmailAddress $email): bool
    {
        try {
            return EmailAddress::ofAnySpelling($subject)->isTheSameMailboxAs($email);
        } catch (InvalidArgumentException) {
            return false;
        }
    }

    /**
     * S-56: the one address of the attribute of the e-mail, its domain written as its A-label by the one rule of the
     * domain (S-60) before the core reads the address, which refuses a domain outside ASCII.
     *
     * @throws AssertionRefusedException
     */
    private static function address(UpstreamIdentityProvider $provider, VerifiedAssertion $verified): EmailAddress
    {
        $address = self::oneValue($verified, $provider->emailAttribute);
        if ($address === null) {
            throw new AssertionRefusedException('The attribute of the e-mail holds not one value (spec/saml.md S-56).');
        }
        try {
            return EmailAddress::ofAnySpelling($address);
        } catch (InvalidArgumentException) {
            // the refusal of the core names the address, which no exception of a refusal carries (S-53)
            throw new AssertionRefusedException('The attribute of the e-mail is no address whose domain the rule reads (spec/saml.md S-56, S-60).');
        }
    }

    /**
     * The value of an attribute that holds one, null when it holds none or several.
     */
    private static function oneValue(VerifiedAssertion $verified, string $attribute): ?string
    {
        $values = $verified->values($attribute);
        if (count($values) !== 1) {
            return null;
        }

        return $values[0];
    }
}
