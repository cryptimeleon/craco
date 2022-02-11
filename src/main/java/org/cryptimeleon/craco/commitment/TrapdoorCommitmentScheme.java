package org.cryptimeleon.craco.commitment;

/**
 * Interface used to implement trapdoor commitment schemes.
 */
public interface TrapdoorCommitmentScheme extends CommitmentScheme{

    /**
     * Creates a key pair consisting of a commitment key and a trapdoor key
     *
     * @return the {@link TrapdoorCommitmentKeyPair} containing the {@link OpenValue} and {@link TrapdoorValue}
     *         associated with the scheme
     * */
    TrapdoorCommitmentKeyPair<? extends OpenValue, ? extends TrapdoorValue> generateKeyPair();

}
