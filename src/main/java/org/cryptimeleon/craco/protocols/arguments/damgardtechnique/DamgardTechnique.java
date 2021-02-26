package org.cryptimeleon.craco.protocols.arguments.damgardtechnique;

import org.cryptimeleon.craco.commitment.CommitmentPair;
import org.cryptimeleon.craco.commitment.CommitmentScheme;
import org.cryptimeleon.craco.commitment.hashthencommit.HashThenCommitCommitmentScheme;
import org.cryptimeleon.craco.commitment.pedersen.PedersenCommitmentScheme;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.common.ByteArrayImplementation;
import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.craco.protocols.arguments.sigma.*;
import org.cryptimeleon.math.expressions.bool.BooleanExpression;
import org.cryptimeleon.math.hash.impl.VariableOutputLengthHashFunction;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.groups.Group;

import java.math.BigInteger;

/**
 * This class provides Damgard's Technique. Damgard's Technique is a construction to improve Sigma-Protocols in order to
 * provide security against concurrent adversaries. The resulting protocol is a 'Concurrent black-box zero knowledge
 * three-way interactive argument of knowledge'.
 * <p>
 * Damgard's Technique is applied on a given Sigma-Protocol. A given commitment scheme is used to achieve the security
 * improvement by changing the original given Sigma-Protocol in the following way:
 * <ol>
 * <li> Instead of sending the announcement the protocol sends the commitment of the announcement.
 * <li> The last message additionally contains the original announcement and the verify-value of the commitment of the
 * announcement. These information are then used in the verify to check validity of the commitment as well as the
 * original verification from the Sigma-Protocol.
 * </ol>
 * <p>
 * The result of Damgard's Technique is a 'Concurrent black-box zero knowledge three-way interactive argument of
 * knowledge'.
 */
public class DamgardTechnique implements SigmaProtocol {

    protected SigmaProtocol innerProtocol;
    protected CommitmentScheme commitmentScheme;

    /**
     *
     * @param innerProtocol the sigma protocol to transform
     * @param commitmentScheme a commitment scheme for arbitrary bit strings (ByteArrayImplementation)
     */
    public DamgardTechnique(SigmaProtocol innerProtocol, CommitmentScheme commitmentScheme) {
        this.innerProtocol = innerProtocol;
        this.commitmentScheme = commitmentScheme;
    }

    @Override
    public DamgardAnnouncementSecret generateAnnouncementSecret(CommonInput commonInput, SecretInput secretInput) {
        AnnouncementSecret innerSecret = innerProtocol.generateAnnouncementSecret(commonInput, secretInput);
        Announcement innerAnnouncement = innerProtocol.generateAnnouncement(commonInput, secretInput, innerSecret);
        CommitmentPair commitment = commitmentScheme.commit(announcementToCommitmentPlaintext(innerAnnouncement));
        return new DamgardAnnouncementSecret(innerSecret, innerAnnouncement, commitment);
    }

    @Override
    public Announcement generateAnnouncement(CommonInput commonInput, SecretInput secretInput, AnnouncementSecret announcementSecret) {
        return new DamgardAnnouncement(((DamgardAnnouncementSecret) announcementSecret).commitment.getCommitment());
    }

    @Override
    public Challenge generateChallenge(CommonInput commonInput) {
        return innerProtocol.generateChallenge(commonInput);
    }

    @Override
    public Response generateResponse(CommonInput commonInput, SecretInput secretInput, Announcement announcement, AnnouncementSecret announcementSecret, Challenge challenge) {
        Response innerResponse = innerProtocol.generateResponse(commonInput,
                secretInput,
                ((DamgardAnnouncementSecret) announcementSecret).innerAnnouncement,
                ((DamgardAnnouncementSecret) announcementSecret).innerAnnouncementSecret,
                challenge);
        Announcement innerAnnouncement = ((DamgardAnnouncementSecret) announcementSecret).innerAnnouncement;

        Representation compressedTranscript = innerProtocol.compressTranscript(commonInput, new SigmaProtocolTranscript(innerAnnouncement, challenge, innerResponse));
        return new DamgardResponse(innerResponse, innerAnnouncement, ((DamgardAnnouncementSecret) announcementSecret).commitment.getOpenValue(), compressedTranscript);
    }

    @Override
    public BooleanExpression checkTranscriptAsExpression(CommonInput commonInput, Announcement announcement, Challenge challenge, Response response) {
        if (!commitmentScheme.verify(((DamgardAnnouncement) announcement).getCommitment(),
                ((DamgardResponse) response).getOpenValue(),
                announcementToCommitmentPlaintext(((DamgardResponse) response).getInnerAnnouncement()))) {
            return BooleanExpression.FALSE;
        }

        return innerProtocol.checkTranscriptAsExpression(commonInput,
                ((DamgardResponse) response).getInnerAnnouncement(),
                challenge,
                ((DamgardResponse) response).getInnerResponse());
    }

    @Override
    public SigmaProtocolTranscript generateSimulatedTranscript(CommonInput commonInput, Challenge challenge) {
        SigmaProtocolTranscript inner = innerProtocol.generateSimulatedTranscript(commonInput, challenge);
        Representation compressedInnerTranscript = innerProtocol.compressTranscript(commonInput, inner);
        CommitmentPair commitmentAndOpening = commitmentScheme.commit(announcementToCommitmentPlaintext(inner.getAnnouncement()));
        return new SigmaProtocolTranscript(new DamgardAnnouncement(commitmentAndOpening.getCommitment()),
                challenge,
                new DamgardResponse(inner.getResponse(), inner.getAnnouncement(), commitmentAndOpening.getOpenValue(), compressedInnerTranscript));
    }

    @Override
    public DamgardAnnouncement recreateAnnouncement(CommonInput commonInput, Representation repr) {
        return new DamgardAnnouncement(repr, commitmentScheme);
    }

    @Override
    public Challenge recreateChallenge(CommonInput commonInput, Representation repr) {
        return innerProtocol.recreateChallenge(commonInput, repr);
    }

    @Override
    public DamgardResponse recreateResponse(CommonInput commonInput, Announcement announcement, Challenge challenge, Representation repr) {
        SigmaProtocolTranscript transcript = innerProtocol.decompressTranscript(commonInput, challenge, repr.obj().get("compressedTranscript"));
        return new DamgardResponse(transcript.getResponse(), transcript.getAnnouncement(),
                commitmentScheme.restoreOpenValue(repr.obj().get("openValue")), repr.obj().get("compressedTranscript"));
    }

    @Override
    public Challenge createChallengeFromBytes(CommonInput commonInput, byte[] bytes) {
        return innerProtocol.createChallengeFromBytes(commonInput, bytes);
    }

    @Override
    public BigInteger getChallengeSpaceSize() {
        return innerProtocol.getChallengeSpaceSize();
    }

    protected PlainText announcementToCommitmentPlaintext(Announcement innerAnnouncement) {
        return new ByteArrayImplementation(innerAnnouncement.getUniqueByteRepresentation());
    }

    public static CommitmentScheme generateCommitmentScheme(Group group) {
        return new HashThenCommitCommitmentScheme(
                new PedersenCommitmentScheme(group, 1),
                new VariableOutputLengthHashFunction((group.size().bitLength()-1)/8)
        );
    }
}
