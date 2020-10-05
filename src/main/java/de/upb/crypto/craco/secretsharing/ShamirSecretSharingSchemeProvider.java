package de.upb.crypto.craco.secretsharing;

import de.upb.crypto.craco.abe.interfaces.LinearSecretSharing;
import de.upb.crypto.craco.common.interfaces.policy.Policy;
import de.upb.crypto.craco.common.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Objects;

/**
 * This {@link SecretSharingSchemeProvider} will create instances of {@link ShamirSecretSharing}
 * with each call to {@link SecretSharingSchemeProvider#createLSSSInstance}
 */
public class ShamirSecretSharingSchemeProvider implements SecretSharingSchemeProvider {

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
