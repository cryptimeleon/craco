package org.cryptimeleon.craco.protocols.arguments.sigma.partial;

import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.craco.protocols.arguments.sigma.*;
import org.cryptimeleon.math.expressions.bool.BooleanExpression;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.cartesian.Vector;

/**
 * The AND composition of two (or more) SigmaProtocols.
 * Meaning that in order to run this protocol, the prover must have knowledge of valid secret input for both (sub)protocols.
 * <br>
 * To use:
 * <ol>
 * <li>Instantiate this protocol with the list of protocols to compose.</li>
 * <li>The common input for this protocol is a {@link org.cryptimeleon.craco.protocols.CommonInput.CommonInputVector} of the subprotocols' common inputs</li>
 * <li>The secret input for this protocol is a {@link org.cryptimeleon.craco.protocols.SecretInput.SecretInputVector} of the subprotocols' common inputs</li>
 * </ol>
 *
 * Depending on your use-case, {@link ProofOfPartialKnowledge} may be more convenient for you.
 */
public class AndProof implements SigmaProtocol {
    public final Vector<SigmaProtocol> protocols;

    public AndProof(SigmaProtocol... protocols) {
        this.protocols = new Vector<SigmaProtocol>(protocols);
    }

    @Override
    public AnnouncementSecret generateAnnouncementSecret(CommonInput commonInput, SecretInput secretInput) {
        return protocols.map((i, protocol) -> protocol.generateAnnouncementSecret(
                ((CommonInput.CommonInputVector) commonInput).get(i),
                ((SecretInput.SecretInputVector) secretInput).get(i)
                ),
            AnnouncementSecret.AnnouncementSecretVector::new);
    }

    @Override
    public Announcement generateAnnouncement(CommonInput commonInput, SecretInput secretInput, AnnouncementSecret announcementSecret) {
        return protocols.map((i, protocol) -> protocol.generateAnnouncement(
                ((CommonInput.CommonInputVector) commonInput).get(i),
                ((SecretInput.SecretInputVector) secretInput).get(i),
                ((AnnouncementSecret.AnnouncementSecretVector) announcementSecret).get(i)
                ),
            Announcement.AnnouncementVector::new);
    }

    @Override
    public ChallengeSpace getChallengeSpace(CommonInput commonInput) {
        return protocols.get(0).getChallengeSpace(((CommonInput.CommonInputVector) commonInput).get(0));
    }

    @Override
    public Response generateResponse(CommonInput commonInput, SecretInput secretInput, Announcement announcement, AnnouncementSecret announcementSecret, Challenge challenge) {
        return protocols.map((i, protocol) -> protocol.generateResponse(
                ((CommonInput.CommonInputVector) commonInput).get(i),
                ((SecretInput.SecretInputVector) secretInput).get(i),
                ((Announcement.AnnouncementVector) announcement).get(i),
                ((AnnouncementSecret.AnnouncementSecretVector) announcementSecret).get(i),
                challenge //they all use the same challenge
                ),
            Response.ResponseVector::new);
    }

    @Override
    public BooleanExpression checkTranscriptAsExpression(CommonInput commonInput, Announcement announcement, Challenge challenge, Response response) {
        return protocols.map((i, protocol) -> protocol.checkTranscriptAsExpression(
                ((CommonInput.CommonInputVector) commonInput).get(i),
                ((Announcement.AnnouncementVector) announcement).get(i),
                challenge,
                ((Response.ResponseVector) response).get(i)
                ))
                .reduce(BooleanExpression::and, BooleanExpression.TRUE);
    }

    @Override
    public SigmaProtocolTranscript generateSimulatedTranscript(CommonInput commonInput, Challenge challenge) {
        Vector<SigmaProtocolTranscript> transcriptVector = protocols.map((i, protocol) -> protocol.generateSimulatedTranscript(
                ((CommonInput.CommonInputVector) commonInput).get(i),
                challenge
        ));
        Announcement.AnnouncementVector announcement = transcriptVector.map(SigmaProtocolTranscript::getAnnouncement, Announcement.AnnouncementVector::new);
        Response.ResponseVector response = transcriptVector.map(SigmaProtocolTranscript::getResponse, Response.ResponseVector::new);
        return new SigmaProtocolTranscript(announcement, challenge, response);
    }

    @Override
    public Announcement restoreAnnouncement(CommonInput commonInput, Representation repr) {
        return protocols.map((i, protocol) -> protocol.restoreAnnouncement(
                ((CommonInput.CommonInputVector) commonInput).get(i),
                repr.list().get(i)
                ),
            Announcement.AnnouncementVector::new);
    }

    @Override
    public Response restoreResponse(CommonInput commonInput, Announcement announcement, Challenge challenge, Representation repr) {
        return protocols.map((i, protocol) -> protocol.restoreResponse(
                ((CommonInput.CommonInputVector) commonInput).get(i),
                ((Announcement.AnnouncementVector) announcement).get(i),
                challenge,
                repr.list().get(i)
                ),
            Response.ResponseVector::new);
    }
}
