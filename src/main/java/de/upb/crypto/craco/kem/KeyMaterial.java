package de.upb.crypto.craco.kem;

import de.upb.crypto.craco.common.interfaces.EncryptionKey;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;

/**
 * Used to derive a key that is encapsulated by {@link KeyEncapsulationMechanism#encaps(EncryptionKey)}.
 * <p>
 * Key material is not by itself a good key, but is the result of some
 * high entropy source (which is not necessarily close to the uniform distribution).
 * You should apply a key derivation function to a {@code KeyMaterial} in order to
 * receive a proper key (typically close to uniformly distributed bit strings).
 */
public interface KeyMaterial extends UniqueByteRepresentable {


    /**
     * Returns the min entropy, of the key material's source X, i.e.
     * \(-\log_2(\max\{Pr[X = x]\})\), where the maximum is over all possible x.
     */
    int getMinEntropyInBit();
}
