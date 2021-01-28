package de.upb.crypto.craco.common.predicate;

import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * A {@code CiphertextIndex} is an object associated to an encryption key such that
 * only a decryption key with a {@link KeyIndex} that satisfies some predication
 * can decrypt its ciphertexts.
 *
 */
public interface CiphertextIndex extends StandaloneRepresentable {

}
