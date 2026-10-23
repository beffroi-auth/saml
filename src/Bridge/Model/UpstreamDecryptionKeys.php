<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use function array_map;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Key\UnsealedKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Exception\UnsupportedAlgorithmException;
use Beffroi\Core\Port\KeptDecryptionKeyProviderInterface;
use Beffroi\Core\Port\KeyAlgorithmsInterface;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Saml\Bridge\Pki\RsaPrivateKey;
use Beffroi\Saml\Domain\Key\SamlEncryptionAlgorithmInterface;
use Beffroi\Saml\Domain\Key\UpstreamEncryptionKeys;
use Beffroi\Xml\Enc\DecryptionKeyInterface;
use Beffroi\Xml\Enc\Exception\InvalidKey;
use Beffroi\Xml\Enc\PrivateDecryptionKey;

/**
 * The key that opens what one upstream identity provider encrypted (spec/saml.md S-66, section 6.13): what the
 * assertion consumer service gives the model's IdentityProvider of the provider whose accepted metadata verify the
 * response (withDecryptionKey(), model.md section 5.5, issue #784), so that the key that opens a response is the key
 * whose certificate went to the provider that signed it, and to no other (enc.md E-15).
 *
 * Its keys are those of that provider in service, staged, active and retiring, read from the key store at each call, so
 * that a key that has retired since is not among them, opened by the KMS through the core as one set, of the algorithm
 * wired for that provider and of no other: the core keeps them open for the process and forgets every other key of
 * that algorithm it held, so that a key that has retired since the last response leaves a worker that lives for months.
 * They are opened here, before the response is read: a KMS that does not answer refuses the response before anything
 * of it is decrypted, and nothing of the KMS happens inside the decryption, whose failure is one (enc.md E-3).
 */
final readonly class UpstreamDecryptionKeys
{
    public function __construct(
        private TenantKeyRepositoryInterface $keys,
        private KeyAlgorithmsInterface $algorithms,
        private KeptDecryptionKeyProviderInterface $opened,
    ) {
    }

    /**
     * @param string $identityProvider the entity ID of the provider whose accepted metadata verify the response
     *
     * @throws KmsUnavailableException when the KMS does not answer to open a key that is not open yet
     * @throws KeyNotFoundException when a key retired between the reading of the store and its opening
     * @throws RuntimeException when a key of the provider shares its modulus with another key in service (S-64)
     * @throws InvalidArgumentException when a private half is not the one of its public JWK
     * @throws InvalidKey when a key is not one Enc decrypts with
     *
     * @return DecryptionKeyInterface|null null when nothing is wired for that provider or the tenant holds no key of it
     *                                     in service: the model then refuses its saml:EncryptedAssertion by name
     */
    public function of(Tenant $tenant, string $identityProvider): ?DecryptionKeyInterface
    {
        try {
            $algorithm = $this->algorithms->named(SamlEncryptionAlgorithmInterface::NAME_PREFIX . $identityProvider);
        } catch (UnsupportedAlgorithmException) {
            return null;
        }
        if (! $algorithm instanceof SamlEncryptionAlgorithmInterface) {
            return null;
        }
        $kids = array_map(
            static fn (TenantKey $key): string => $key->kid,
            UpstreamEncryptionKeys::of($this->keys->findInService($tenant), $identityProvider)->keys,
        );
        // asked even with none, so that the core forgets what it held of a provider whose keys have all retired
        $opened = $this->opened->keptDecryptionKeys($tenant, $algorithm, $kids);
        if ($opened === []) {
            return null;
        }

        return new ProviderDecryptionKey(array_map(
            static fn (UnsealedKey $key): PrivateDecryptionKey => PrivateDecryptionKey::fromPem(RsaPrivateKey::pem($key)),
            $opened,
        ));
    }
}
