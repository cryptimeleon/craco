package de.upb.crypto.craco.common.interfaces.pe;

import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;

/**
 * A key used to generate {@link DecryptionKey}s in a {@link PredicateEncryptionScheme}.
 * This key will typically be created during setup of a scheme (for which there is no common interface).
 * <p>
 * {@code MasterSecret}s are {@link Representable} and can be
 * restored from their {@link Representation} using {@link PredicateEncryptionScheme#getMasterSecret(Representation)}.
 *
 *
 */
public interface MasterSecret extends Representable {
    public final static String RECOVERY_METHOD = "getMasterSecret";
}
