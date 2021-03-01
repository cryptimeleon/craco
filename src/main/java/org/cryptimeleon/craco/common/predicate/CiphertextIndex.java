package org.cryptimeleon.craco.common.predicate;

import org.cryptimeleon.math.serialization.StandaloneRepresentable;

/**
 * A {@code CiphertextIndex} is an object associated to an encryption key such that
 * only a decryption key with a {@link KeyIndex} that satisfies some predication
 * can decrypt its ciphertexts.
 *
 */
public interface CiphertextIndex extends StandaloneRepresentable {

}
