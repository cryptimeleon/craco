package de.upb.crypto.craco.common.predicate;

import de.upb.crypto.craco.enc.DecryptionKey;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * A {@code KeyIndex} is an object associated to a {@link DecryptionKey} such that only ciphertexts
 * generated with an encryption key with a {@link CiphertextIndex} that satisfies
 * some predicate can be decrypted by it.
 *
 * @author Jan
 */
public interface KeyIndex extends StandaloneRepresentable {

}
