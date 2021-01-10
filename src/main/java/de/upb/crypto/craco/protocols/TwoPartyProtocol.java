package de.upb.crypto.craco.protocols;

/**
 * An interactive protocol between two parties.
 */
public interface TwoPartyProtocol {
    de.upb.crypto.craco.protocols.TwoPartyProtocolInstance instantiateProtocol(String role, de.upb.crypto.craco.protocols.CommonInput commonInput, de.upb.crypto.craco.protocols.SecretInput secretInput);

    /**
     * Returns names for the roles of the participants in this protocol (e.g., "prover" or "verifier" in the case of an {@link de.upb.crypto.craco.protocols.arguments.InteractiveArgument})
     */
    String[] getRoleNames();

    /**
     * Returns the role that sends the first message.
     */
    String getFirstMessageRole();
}
