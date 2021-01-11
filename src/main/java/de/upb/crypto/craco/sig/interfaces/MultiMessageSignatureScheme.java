package de.upb.crypto.craco.sig.interfaces;

import de.upb.crypto.craco.common.MessageBlock;

/**
 * A {@code MultiMessageSignatureScheme} is one where the sign and verify algorithms take a list of messages as input
 * instead of a single message.
 * <p>
 * This is implemented as the special case of a single-message scheme
 * where the signed message is of type {@link MessageBlock}.
 * <p>
 * This interface introduces some helper methods for this case.
 *
 * @author Jan
 */
public interface MultiMessageSignatureScheme extends SignatureScheme {

}
