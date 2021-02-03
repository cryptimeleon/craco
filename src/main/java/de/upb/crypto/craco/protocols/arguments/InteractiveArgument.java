package de.upb.crypto.craco.protocols.arguments;

import de.upb.crypto.craco.protocols.CommonInput;
import de.upb.crypto.craco.protocols.SecretInput;
import de.upb.crypto.craco.protocols.TwoPartyProtocol;

/**
 * An argument, i.e. a two-party protocol with roles "prover" and "verifier"
 */
public interface InteractiveArgument extends TwoPartyProtocol {
    String PROVER_ROLE = "prover";
    String VERIFIER_ROLE = "verifier";

    @Override
    default String[] getRoleNames() {
        return new String[]{PROVER_ROLE, VERIFIER_ROLE};
    }

    @Override
    InteractiveArgumentInstance instantiateProtocol(String role, CommonInput commonInput, SecretInput secretInput);

    default InteractiveArgumentInstance instantiateProver(CommonInput commonInput, SecretInput witness) {
        return instantiateProtocol(PROVER_ROLE, commonInput, witness);
    }

    default InteractiveArgumentInstance instantiateVerifier(CommonInput commonInput) {
        return instantiateProtocol(VERIFIER_ROLE, commonInput, null);
    }
}
