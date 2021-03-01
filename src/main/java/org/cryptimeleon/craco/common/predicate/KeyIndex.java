package org.cryptimeleon.craco.common.predicate;

import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.math.serialization.StandaloneRepresentable;

/**
 * A {@code KeyIndex} is an object associated to a {@link DecryptionKey} such that only ciphertexts
 * generated with an encryption key with a {@link CiphertextIndex} that satisfies
 * some predicate can be decrypted by it.
 *
 *
 */
public interface KeyIndex extends StandaloneRepresentable {

}
