package de.upb.crypto.craco.secretsharing;

import de.upb.crypto.craco.abe.interfaces.LinearSecretSharing;
import de.upb.crypto.craco.common.interfaces.policy.Policy;
import de.upb.crypto.craco.common.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.structures.zn.Zp;

/**
 * Represents a provider that can create instances of {@link LinearSecretSharing}
 * to be used for {@link ThresholdTreeSecretSharing}.
 */
public interface SecretSharingSchemeProvider extends StandaloneRepresentable {
    /**
     * Creates a linear secret sharing scheme instance for the given {@code ThresholdPolicy}.
     *
     * @param policy {@link ThresholdPolicy} to create a LSSS for
     * @param field  {@link Zp} to define the shares and secret of the resulting scheme
     * @return an LSSS instance for the given policy based on the given field
     */
    LinearSecretSharing<Policy> createLSSSInstance(ThresholdPolicy policy, Zp field);
}
