package de.upb.crypto.craco.kem;

import de.upb.crypto.craco.common.interfaces.EncryptionKey;
import de.upb.crypto.craco.common.interfaces.EncryptionScheme;
import de.upb.crypto.craco.common.interfaces.SymmetricKey;
import de.upb.crypto.craco.common.interfaces.pe.PredicateKEM;

/**
 * A KEM that implements the standard hybrid construction, meaning {@link #encaps(EncryptionKey)}
 * generates a random key and encrypts it afterwards with some encryption
 * scheme.
 * <p>
 * Implementations of this abstract class need to define how to generate random
 * plaintexts for the encryption scheme and how to derive a secret key (for a
 * symmetric scheme) from the random plaintext (key derivation function).
 */

public abstract class AbstractHybridPredicateKEM extends AbstractHybridConstructionKEM
        implements PredicateKEM<SymmetricKey> {

    public AbstractHybridPredicateKEM(EncryptionScheme scheme, KeyDerivationFunction<? extends SymmetricKey> kdf) {
        super(scheme, kdf);
    }

    public AbstractHybridPredicateKEM(EncryptionScheme scheme) {
        super(scheme, new HashBasedKeyDerivationFunction());
    }
}
