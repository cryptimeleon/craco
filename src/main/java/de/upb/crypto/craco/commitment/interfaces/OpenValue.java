package de.upb.crypto.craco.commitment.interfaces;

import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * Marker interface for the open value of a {@link CommitmentScheme} reflecting the theoretical properties of
 * 'Commitment
 * Schemes' in combination with these interfaces:
 * {@link CommitmentScheme}, {@link CommitmentSchemePublicParameters}, {@link CommitmentSchemePublicParametersGen},
 * {@link CommitmentPair} and {@link Commitment}.
 * The implementation of this interface has to contain all values for open() or verify() of a {@link Commitment}.
 * Furthermore, it is part of the {@link CommitmentPair}.
 */
public interface OpenValue extends StandaloneRepresentable, UniqueByteRepresentable {
}
