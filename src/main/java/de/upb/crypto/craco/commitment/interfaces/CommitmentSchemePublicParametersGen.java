package de.upb.crypto.craco.commitment.interfaces;


/**
 * Interface for 'setup()-method' of a {@link CommitmentScheme} and reflecting the theoretical properties of 'Commitment
 * Schemes' in combination with these interfaces:
 * {@link CommitmentScheme}, {@link CommitmentSchemePublicParameters}, {@link CommitmentPair}, {@link CommitmentValue}
 * and {@link OpenValue}.
 */
public interface CommitmentSchemePublicParametersGen {

    /**
     * This setup generates {@link CommitmentSchemePublicParameters} in order to use the {@link CommitmentScheme}.
     *
     * @param lambda           security parameter
     * @param numberOfMessages the number of messages
     * @return {@link CommitmentSchemePublicParameters} for using the {@link CommitmentScheme}.
     */
    CommitmentSchemePublicParameters setup(int lambda, int numberOfMessages);
}
