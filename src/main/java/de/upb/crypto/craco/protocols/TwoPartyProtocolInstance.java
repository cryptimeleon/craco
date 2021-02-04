package de.upb.crypto.craco.protocols;

import de.upb.crypto.math.serialization.Representation;

/**
 * An instance of a {@link TwoPartyProtocol}, modeling a single protocol run from one of the roles' perspective.
 */
public interface TwoPartyProtocolInstance {
    TwoPartyProtocol getProtocol();
    String getRoleName();

    /**
     * Returns true iff this role sends the first message of this protocol.
     */
    default boolean sendsFirstMessage() {
        return getProtocol().getFirstMessageRole().equals(getRoleName());
    }

    /**
     * Outputs the next message this protocol instance demands to be sent to the other party.
     * @param received the message recently received from the other party 
     *                 or null if this is the first round and no messages have been sent yet
     * @return the message {@code m} to be sent to the other party (who then calls {@code nextMessage(m)} on their end). 
     *         If {@code nextMessage} returns null, the protocol has terminated
     */
    Representation nextMessage(Representation received);

    /**
     * Returns true if the protocol is done, meaning no further calls to {@code nextMessage()} are necessary.
     */
    boolean hasTerminated();
}
