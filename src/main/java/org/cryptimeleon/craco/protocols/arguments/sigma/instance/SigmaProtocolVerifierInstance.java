package org.cryptimeleon.craco.protocols.arguments.sigma.instance;

import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.craco.protocols.arguments.InteractiveArgument;
import org.cryptimeleon.craco.protocols.arguments.sigma.SigmaProtocol;
import org.cryptimeleon.math.serialization.Representation;

public class SigmaProtocolVerifierInstance extends SigmaProtocolInstance {
    protected State state = State.NOTHING;

    enum State {
        NOTHING,
        SENT_CHALLENGE,
        RECEIVED_RESPONSE
    }

    public SigmaProtocolVerifierInstance(SigmaProtocol protocol, CommonInput commonInput) {
        super(protocol, commonInput);
    }

    @Override
    public String getRoleName() {
        return InteractiveArgument.VERIFIER_ROLE;
    }

    @Override
    public Representation nextMessage(Representation received) {
        switch (state) {
            case NOTHING: //receiving announcement
                announcement = protocol.recreateAnnouncement(commonInput, received);
                challenge = protocol.generateChallenge(commonInput);
                state = State.SENT_CHALLENGE;
                return challenge.getRepresentation();
            case SENT_CHALLENGE: //receiving response
                response = protocol.recreateResponse(commonInput, announcement, challenge, received);
                state = State.RECEIVED_RESPONSE;
                return null; //done
            case RECEIVED_RESPONSE:
                return null; //done with the protocol. We actually should not have received any message anymore.
            default:
                throw new IllegalStateException("Unexpected state for Sigma protocol instance: "+state.toString());
        }
    }

    @Override
    public boolean hasTerminated() {
        return state == State.RECEIVED_RESPONSE;
    }
}
