package de.upb.crypto.craco.interfaces.signature;

/**
 * A MultiMessageSignatureScheme is one where Sign() and Verify() take lists
 * of messages as input.
 * <p>
 * This is implemented as the special case of a single message scheme
 * where the signed message is of Type MessageBlock.
 * <p>
 * This interface introduces some helper methods for this case.
 *
 * @author Jan
 */
public interface MultiMessageSignatureScheme extends SignatureScheme {

}
