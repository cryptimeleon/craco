package de.upb.crypto.craco.secretsharing.shamir;

import de.upb.crypto.craco.secretsharing.LinearSecretSharing;
import de.upb.crypto.craco.secretsharing.policy.Policy;
import de.upb.crypto.craco.secretsharing.policy.ThresholdPolicy;
import de.upb.crypto.craco.secretsharing.SecretSharingSchemeProvider;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.rings.zn.Zp;

import java.util.Objects;

/**
 * A {@link SecretSharingSchemeProvider} that can create instances of {@link ShamirSecretSharing}.
 */
public class ShamirSecretSharingSchemeProvider implements SecretSharingSchemeProvider {

    /**
     * Creates a new {@code ShamirSecretSharing} instance for the given {@link ThresholdPolicy} and {@code Zp}.
     *
     * @param policy {@link ThresholdPolicy} to create a LSSS for
     * @param field  {@link Zp} to define the shares and secret of the resulting scheme
     * @return a {@code ShamirSecretSharing} instance for the given policy based on the given field
     */
    @Override
    public LinearSecretSharing<Policy> createLSSSInstance(ThresholdPolicy policy, Zp field) {
        return new ShamirSecretSharing(policy, field);
    }

    public ShamirSecretSharingSchemeProvider() {
    }

    public ShamirSecretSharingSchemeProvider(Representation representation) {

    }

    @Override
    public Representation getRepresentation() {
        return new ObjectRepresentation();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        return o != null && getClass() == o.getClass();
    }

    @Override
    public int hashCode() {
        return Objects.hash(getClass().getName());
    }
}
