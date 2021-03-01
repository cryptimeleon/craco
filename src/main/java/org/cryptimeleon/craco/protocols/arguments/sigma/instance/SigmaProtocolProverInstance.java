package org.cryptimeleon.craco.protocols.arguments.sigma.instance;

import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.craco.protocols.arguments.InteractiveArgument;
import org.cryptimeleon.craco.protocols.arguments.sigma.SigmaProtocol;
import org.cryptimeleon.math.serialization.Representation;

public class SigmaProtocolProverInstance extends SigmaProtocolInstance {
    protected State state = State.NOTHING;

    public enum State {
        NOTHING,
        SENT_ANNOUNCEMENT,
        SENT_RESPONSE
    }

    public SigmaProtocolProverInstance(SigmaProtocol protocol, CommonInput commonInput, SecretInput secretInput) {
        super(protocol, commonInput, secretInput);
    }

    @Override
    public String getRoleName() {
        return InteractiveArgument.PROVER_ROLE;
    }

    @Override
    public Representation nextMessage(Representation received) {
        switch (state) {
            case NOTHING:
                announcementSecret = protocol.generateAnnouncementSecret(commonInput, secretInput);
                announcement = protocol.generateAnnouncement(commonInput, secretInput, announcementSecret);
                state = State.SENT_ANNOUNCEMENT;
                return announcement.getRepresentation();
            case SENT_ANNOUNCEMENT:
                challenge = protocol.restoreChallenge(commonInput, received);
                state = State.SENT_RESPONSE;
                response = protocol.generateResponse(commonInput, secretInput, announcement, announcementSecret, challenge);
                return response.getRepresentation();
            case SENT_RESPONSE:
                return null; //done with the protocol. We actually should not have received any message anymore.
            default:
                throw new IllegalStateException("Unexpected state for Sigma protocol instance: "+state.toString());
        }
    }

    @Override
    public boolean hasTerminated() {
        return state == State.SENT_RESPONSE;
    }
}
