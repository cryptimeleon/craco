package de.upb.crypto.craco.protocols.arguments.sigma;

import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.Representable;

/**
 * A {@link SigmaProtocol}'s second message.
 */
public interface Challenge extends Representable, UniqueByteRepresentable {

}
