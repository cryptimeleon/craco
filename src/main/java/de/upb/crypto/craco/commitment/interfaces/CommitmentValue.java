package de.upb.crypto.craco.commitment.interfaces;

import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * Marker interface for the commitment value of a {@link CommitmentScheme} reflecting the theoretical properties of
 * 'Commitment Schemes' in combination with these interfaces:
 * {@link CommitmentScheme}, {@link CommitmentSchemePublicParameters}, {@link CommitmentSchemePublicParametersGen},
 * {@link CommitmentPair} and {@link OpenValue}.
 * The implementation of this interface has to contains the commitment value.
 * Furthermore, it is part of the {@link CommitmentPair}.
 */
public interface CommitmentValue extends StandaloneRepresentable, UniqueByteRepresentable {
}
