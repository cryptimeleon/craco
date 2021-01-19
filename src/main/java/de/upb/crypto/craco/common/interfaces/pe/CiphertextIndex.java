package de.upb.crypto.craco.common.interfaces.pe;

import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * A {@code CiphertextIndex} is an object associated to an encryption key such that
 * only a decryption key with a {@link KeyIndex} that satisfies {@link PredicateEncryptionScheme#getPredicate()}}
 * can decrypt its ciphertexts.
 *
 * @see PredicateEncryptionScheme#generateEncryptionKey(CiphertextIndex)
 * @see PredicateEncryptionScheme#encrypt(PlainText, CiphertextIndex) 
 *
 * @author Jan
 */
public interface CiphertextIndex extends StandaloneRepresentable {

}
