package org.cryptimeleon.craco.protocols;

public interface SecretInput {
    SecretInput EMPTY = new EmptySecretInput();

    class EmptySecretInput implements SecretInput {
    }
}
