package de.upb.crypto.craco.protocols;

/**
 * An interactive protocol between two parties.
 */
public interface TwoPartyProtocol {
    TwoPartyProtocolInstance instantiateProtocol(String role, CommonInput commonInput, SecretInput secretInput);

    /**
     * Returns names for the roles of the participants in this protocol (e.g., "prover" or "verifier" in the case of an {@link de.upb.crypto.craco.protocols.arguments.InteractiveArgument})
     */
    String[] getRoleNames();

    /**
     * Returns the role that sends the first message.
     */
    String getFirstMessageRole();
}
