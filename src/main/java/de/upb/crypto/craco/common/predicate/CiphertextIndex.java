package de.upb.crypto.craco.common.predicate;

import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * A {@code CiphertextIndex} is an object associated to an encryption key such that
 * only a decryption key with a {@link KeyIndex} that satisfies some predication
 * can decrypt its ciphertexts.
 *
<<<<<<< HEAD:src/main/java/de/upb/crypto/craco/common/predicate/CiphertextIndex.java
 * @author Jan
=======
 * @see PredicateEncryptionScheme#generateEncryptionKey(CiphertextIndex)
 * @see PredicateEncryptionScheme#encrypt(PlainText, CiphertextIndex) 
 *
 *
>>>>>>> upd-release:src/main/java/de/upb/crypto/craco/common/interfaces/pe/CiphertextIndex.java
 */
public interface CiphertextIndex extends StandaloneRepresentable {

}
