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
 * spec/saml.md S-53 to S-57, section 6.14 steps 2 to 7
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
     * Section 6.14 steps 2 to 6
     *
     * @param array<array-key, mixed> $fields
     * @param string $identityProvider the entity ID of the provider the remembered request went to
     *
     * @throws AssertionRefusedException naming the rule and never a value (M-16)
     * @throws UpstreamAuthenticationFailedException
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     */
    public function receive(Tenant $tenant, array $fields, string $identityProvider, string $requestId): UpstreamAssertion
    {
        $provider = $this->providers->find($tenant, $identityProvider);
        if ($provider === null) {
            throw new AssertionRefusedException('The identity provider the request went to is none this tenant declares (spec/saml.md S-53).');
        }
        $verified = $this->receiver->receive($tenant, $provider, $fields, $requestId);
        // S-54: checked before anything of the assertion is read.
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
     * Section 6.14 step 7, S-56
     *
     * The groups the declaration maps to are found in the tenant by their names and never created.
     *
     * @throws UpstreamProvisioningRefusedException
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
     * S-55
     *
     * Never the address of the person, whatever names it.
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
     * S-55
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
     * S-56, S-60
     *
     * The domain is written as its A-label before the core reads the address, which refuses a domain outside ASCII.
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
            // The refusal of the core names the address, which no refusal carries (S-53).
            throw new AssertionRefusedException('The attribute of the e-mail is no address whose domain the rule reads (spec/saml.md S-56, S-60).');
        }
    }

    /**
     * Null when the attribute holds none or several values.
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
