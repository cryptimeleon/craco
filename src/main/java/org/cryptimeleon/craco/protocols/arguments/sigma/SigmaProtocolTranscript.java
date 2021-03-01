package org.cryptimeleon.craco.protocols.arguments.sigma;

import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.SchnorrChallenge;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.SchnorrFragment;
import org.cryptimeleon.math.serialization.ObjectRepresentation;
import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.serialization.Representation;

/**
 * A transcript contains the messages exchanged during the execution of a three way protocol.
 * <p>
 * These are announcement, challenge and response. Announcement and Response are sent by the Prover to the Verifier,
 * the challenge from the Verifier to the Prover.
 */
public class SigmaProtocolTranscript implements Representable {
    protected Announcement announcement;
    protected Challenge challenge;
    protected Response response;

    public SigmaProtocolTranscript(Announcement announcement, Challenge challenge, Response response) {
        this.announcement = announcement;
        this.challenge = challenge;
        this.response = response;
    }

    public SigmaProtocolTranscript(SigmaProtocol protocol, CommonInput commonInput, Representation repr) {
        announcement = protocol.restoreAnnouncement(commonInput, repr.obj().get("a"));
        challenge = protocol.restoreChallenge(commonInput, repr.obj().get("c"));
        response = protocol.restoreResponse(commonInput, announcement, challenge, repr.obj().get("r"));
    }

    public SigmaProtocolTranscript(SchnorrFragment fragment, Representation repr) {
        announcement = fragment.restoreAnnouncement(repr.obj().get("a"));
        challenge = new SchnorrChallenge(repr.obj().get("c"));
        response = fragment.restoreResponse(announcement, repr.obj().get("r"));
    }

    public Announcement getAnnouncement() {
        return announcement;
    }

    public Challenge getChallenge() {
        return challenge;
    }

    public Response getResponse() {
        return response;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("a", announcement.getRepresentation());
        repr.put("c", challenge.getRepresentation());
        repr.put("r", response.getRepresentation());
        return repr;
    }
}

