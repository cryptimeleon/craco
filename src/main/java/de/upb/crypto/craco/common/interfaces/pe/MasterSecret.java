package de.upb.crypto.craco.common.interfaces.pe;

import de.upb.crypto.math.serialization.Representable;

/**
 * A key used to generate DecryptionKeys in PredicateEncryptionSchemes.
 * This key will typically be created during setup of a scheme (for which there is no common interface).
 * <p>
 * MasterSecrets are Representable and can be
 * restored from Representation using the appropriate method of
 * the PredicateEncryptionScheme interface.
 *
 * @author Jan
 */
public interface MasterSecret extends Representable {
    public final static String RECOVERY_METHOD = "getMasterSecret";
}
