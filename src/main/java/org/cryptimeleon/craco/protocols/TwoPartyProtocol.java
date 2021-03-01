package org.cryptimeleon.craco.protocols;


import org.cryptimeleon.craco.protocols.arguments.InteractiveArgument;
import org.cryptimeleon.math.serialization.Representation;

/**
 * An interactive protocol between two parties.
 */
public interface TwoPartyProtocol {
    TwoPartyProtocolInstance instantiateProtocol(String role, CommonInput commonInput, SecretInput secretInput);

    /**
     * Returns names for the roles of the participants in this protocol (for example, "prover" or "verifier" 
     * in the case of an {@link InteractiveArgument}).
     */
    String[] getRoleNames();

    /**
     * Returns the role that sends the first message.
     */
    String getFirstMessageRole();

    /**
     * Runs the two instances until they both terminate, passing messages directly from one to the other (i.e. no network). <br>
     * Mostly useful for debugging.
     */
    default void runProtocolLocally(TwoPartyProtocolInstance instance0, TwoPartyProtocolInstance instance1) {
        if (instance0.getRoleName().equals(instance1.getRoleName()))
            throw new IllegalArgumentException("Instances must be of different roles");

        TwoPartyProtocolInstance instanceWhosTurnItIs = instance0.sendsFirstMessage() ? instance0 : instance1;
        Representation messageInTransit = null;
        while (!instance0.hasTerminated() || !instance1.hasTerminated()) {
            messageInTransit = instanceWhosTurnItIs.nextMessage(messageInTransit);
            instanceWhosTurnItIs = instanceWhosTurnItIs == instance0 ? instance1 : instance0;
        }
    }
}
