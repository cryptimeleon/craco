package de.upb.crypto.craco.protocols.arguments;

import de.upb.crypto.craco.protocols.TwoPartyProtocolInstance;

public interface InteractiveArgumentInstance extends TwoPartyProtocolInstance {
    /**
     * Called on the verifier after protocol has terminated.
     * Returns true if the protocol is accepting (i.e. the prover was able to convince the verifier)
     */
    boolean isAccepting();

    @Override
    InteractiveArgument getProtocol();
}
