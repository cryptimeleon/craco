package org.cryptimeleon.craco.protocols;

import org.cryptimeleon.math.structures.cartesian.Vector;

import java.util.List;

public interface SecretInput {
    SecretInput EMPTY = new EmptySecretInput();

    class EmptySecretInput implements SecretInput {
    }

    public class SecretInputVector extends Vector<SecretInput> implements SecretInput {
        public SecretInputVector(SecretInput... secretInputs) {
            super(secretInputs);
        }

        public SecretInputVector(List<? extends SecretInput> secretInputs) {
            super(secretInputs);
        }
    }
}
