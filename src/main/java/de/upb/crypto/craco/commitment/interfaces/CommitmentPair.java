package de.upb.crypto.craco.commitment.interfaces;

import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * Interface for the commitment value of a {@link CommitmentScheme} reflecting the theoretical properties of
 * 'Commitment Schemes' in combination with these interfaces:
 * {@link CommitmentScheme}, {@link CommitmentSchemePublicParameters}, {@link CommitmentSchemePublicParametersGen},
 * {@link CommitmentValue} and {@link OpenValue}.
 * The implementation of this interface is a wrapper for the {@link CommitmentValue} and its {@link OpenValue}.
 * Furthermore, it is the returned parameter of the {@link CommitmentScheme}'s commit().
 */
public interface CommitmentPair extends StandaloneRepresentable, UniqueByteRepresentable {

    /**
     * Returns the {@link CommitmentValue} of the {@link CommitmentPair}.
     *
     * @return {@link CommitmentValue}
     */
    CommitmentValue getCommitmentValue();

    /**
     * Returns the {@link OpenValue} of the {@link CommitmentPair}.
     *
     * @return {@link OpenValue}
     */
    OpenValue getOpenValue();
}
