package de.upb.crypto.craco.protocols.arguments;

import de.upb.crypto.craco.protocols.TwoPartyProtocolInstance;

public interface InteractiveArgumentInstance extends TwoPartyProtocolInstance {
    /**
     * Returns true if the protocol is accepting (meaning the prover was able to convince the verifier).
     * Called on the verifier after protocol has terminated.
     */
    boolean isAccepting();

    @Override
    InteractiveArgument getProtocol();
}
