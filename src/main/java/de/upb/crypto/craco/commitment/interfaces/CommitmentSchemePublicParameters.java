package de.upb.crypto.craco.commitment.interfaces;

import de.upb.crypto.craco.common.interfaces.PublicParameters;

/**
 * Marker interface for public parameters of a {@link CommitmentScheme} reflecting the theoretical properties of
 * 'Commitment Schemes' in combination with these interfaces:
 * {@link CommitmentSchemePublicParametersGen}, {@link CommitmentScheme}, {@link CommitmentPair},
 * {@link CommitmentValue} and {@link OpenValue}.
 * The implementation of this interface has to contain all public parameters of its {@link CommitmentScheme}.
 */
public interface CommitmentSchemePublicParameters extends PublicParameters {
}
