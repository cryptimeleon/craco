package org.cryptimeleon.craco.enc;

import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.serialization.Representable;

/**
 * A key that is used to encrypt plaintexts.
 * <p>
 * EncryptionKeys are representable and can be
 * restored from their representation using the appropriate method of
 * the corresponding {@link EncryptionScheme} implementation.
 */
public interface EncryptionKey extends Representable, UniqueByteRepresentable {

}
