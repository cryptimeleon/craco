package org.cryptimeleon.craco.protocols.arguments.sigma.schnorr;

import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.craco.protocols.arguments.sigma.*;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.variables.SchnorrVariable;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.variables.SchnorrVariableAssignment;
import org.cryptimeleon.math.expressions.bool.BooleanExpression;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.serialization.Representation;

/**
 * <p>The protocol version of {@link SendThenDelegateFragment}.</p>
 * <p>
 *     A {@link SchnorrFragment} is always incomplete in the sense that it depends on external variables.
 *     In contrast, a {@link SigmaProtocol} has no external dependencies and, hence, can be run standalone.
 * </p>
 * <p>
 *     An implementation of a {@link SendThenDelegateProtocol} is very similar to an implementation of
 *     a {@link SendThenDelegateFragment}, except that there are no external {@link SchnorrVariable}s and the protocol
 *     must define all its variables itself.
 * </p>
 */
public abstract class SendThenDelegateProtocol implements SigmaProtocol {

    /**
     * Run by the prover to set up (1) the sendFirstValue and
     * (2) witness values for variables this fragment proves knowledge of itself (i.e. those specified in {@link SendThenDelegateProtocol#provideSubprotocolSpec(CommonInput, SendFirstValue, SendThenDelegateFragment.SubprotocolSpecBuilder)}).
     *
     * @see SendThenDelegateFragment#provideProverSpec(SchnorrVariableAssignment, SendThenDelegateFragment.ProverSpecBuilder)
     */
    protected abstract SendThenDelegateFragment.ProverSpec provideProverSpec(CommonInput commonInput, SecretInput secretInput, SendThenDelegateFragment.ProverSpecBuilder builder);
    protected abstract SendFirstValue restoreSendFirstValue(CommonInput commonInput, Representation repr);

    /**
     * @see SendThenDelegateFragment#simulateSendFirstValue()
     */
    protected abstract SendFirstValue simulateSendFirstValue(CommonInput commonInput);

    /**
     * @see SendThenDelegateFragment#provideSubprotocolSpec(SendFirstValue, SendThenDelegateFragment.SubprotocolSpecBuilder)
     */
    protected abstract SendThenDelegateFragment.SubprotocolSpec provideSubprotocolSpec(CommonInput commonInput, SendFirstValue sendFirstValue, SendThenDelegateFragment.SubprotocolSpecBuilder builder);

    /**
     * @see SendThenDelegateFragment#provideAdditionalCheck(SendFirstValue)
     */
    protected abstract BooleanExpression provideAdditionalCheck(CommonInput commonInput, SendFirstValue sendFirstValue);

    @Override
    public abstract ZnChallengeSpace getChallengeSpace(CommonInput commonInput);

    @Override
    public AnnouncementSecret generateAnnouncementSecret(CommonInput commonInput, SecretInput secretInput) {
        TopLevelSchnorrFragment fragment = new TopLevelSchnorrFragment(commonInput, secretInput);
        AnnouncementSecret fragmentAnnouncementSecret = fragment.generateAnnouncementSecret(SchnorrVariableAssignment.EMPTY);

        return new SchnorrAnnouncementSecret(fragment, fragmentAnnouncementSecret);
    }

    @Override
    public Announcement generateAnnouncement(CommonInput commonInput, SecretInput secretInput, AnnouncementSecret announcementSecret) {
        SchnorrAnnouncementSecret announcementSecret1 = (SchnorrAnnouncementSecret) announcementSecret;
        return new SchnorrAnnouncement(announcementSecret1.fragment, announcementSecret1.fragment.generateAnnouncement(SchnorrVariableAssignment.EMPTY, announcementSecret1.fragmentAnnouncementSecret, SchnorrVariableAssignment.EMPTY));
    }

    @Override
    public Response generateResponse(CommonInput commonInput, SecretInput secretInput, Announcement announcement, AnnouncementSecret announcementSecret, Challenge challenge) {
        SchnorrAnnouncementSecret announcementSecret1 = (SchnorrAnnouncementSecret) announcementSecret;
        return announcementSecret1.fragment.generateResponse(SchnorrVariableAssignment.EMPTY, announcementSecret1.fragmentAnnouncementSecret, (ZnChallenge) challenge);
    }

    @Override
    public BooleanExpression checkTranscriptAsExpression(CommonInput commonInput, Announcement announcement, Challenge challenge, Response response) {
        return ((SchnorrAnnouncement) announcement).fragment.checkTranscript(((SchnorrAnnouncement) announcement).fragmentAnnouncement, (ZnChallenge) challenge, response, SchnorrVariableAssignment.EMPTY);
    }

    @Override
    public SigmaProtocolTranscript generateSimulatedTranscript(CommonInput commonInput, Challenge challenge) {
        TopLevelSchnorrFragment fragment = new TopLevelSchnorrFragment(commonInput);
        return fragment.generateSimulatedTranscript((ZnChallenge) challenge, SchnorrVariableAssignment.EMPTY);
    }

    @Override
    public Announcement restoreAnnouncement(CommonInput commonInput, Representation repr) {
        TopLevelSchnorrFragment fragment = new TopLevelSchnorrFragment(commonInput);
        return new SchnorrAnnouncement(fragment, fragment.restoreAnnouncement(repr));
    }

    @Override
    public ZnChallenge restoreChallenge(CommonInput commonInput, Representation repr) {
        return getChallengeSpace(commonInput).restoreChallenge(repr);
    }

    @Override
    public Response restoreResponse(CommonInput commonInput, Announcement announcement, Challenge challenge, Representation repr) {
        return ((SchnorrAnnouncement) announcement).fragment.restoreResponse(((SchnorrAnnouncement) announcement).fragmentAnnouncement, repr);
    }

    private static class SchnorrAnnouncementSecret implements AnnouncementSecret {
        public final TopLevelSchnorrFragment fragment;
        public final AnnouncementSecret fragmentAnnouncementSecret;

        public SchnorrAnnouncementSecret(TopLevelSchnorrFragment fragment, AnnouncementSecret fragmentAnnouncementSecret) {
            this.fragment = fragment;
            this.fragmentAnnouncementSecret = fragmentAnnouncementSecret;
        }
    }

    private static class SchnorrAnnouncement implements Announcement {
        public final SchnorrFragment fragment;
        public final Announcement fragmentAnnouncement;

        public SchnorrAnnouncement(SchnorrFragment fragment, Announcement fragmentAnnouncement) {
            this.fragment = fragment;
            this.fragmentAnnouncement = fragmentAnnouncement;
        }

        @Override
        public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
            return fragmentAnnouncement.updateAccumulator(accumulator);
        }

        @Override
        public Representation getRepresentation() {
            return fragmentAnnouncement.getRepresentation();
        }
    }

    private class TopLevelSchnorrFragment extends SendThenDelegateFragment {
        public final CommonInput commonInput;
        public final SecretInput secretInput;

        public TopLevelSchnorrFragment(CommonInput commonInput, SecretInput secretInput) {
            this.commonInput = commonInput;
            this.secretInput = secretInput;
        }

        public TopLevelSchnorrFragment(CommonInput commonInput) {
            this(commonInput, null);
        }

        @Override
        protected ProverSpec provideProverSpec(SchnorrVariableAssignment externalWitnesses, ProverSpecBuilder builder) {
            return SendThenDelegateProtocol.this.provideProverSpec(commonInput, secretInput, builder);
        }

        @Override
        protected SendFirstValue restoreSendFirstValue(Representation repr) {
            return SendThenDelegateProtocol.this.restoreSendFirstValue(commonInput, repr);
        }

        @Override
        protected SendFirstValue simulateSendFirstValue() {
            return SendThenDelegateProtocol.this.simulateSendFirstValue(commonInput);
        }

        @Override
        protected SubprotocolSpec provideSubprotocolSpec(SendFirstValue sendFirstValue, SubprotocolSpecBuilder builder) {
            return SendThenDelegateProtocol.this.provideSubprotocolSpec(commonInput, sendFirstValue, builder);
        }

        @Override
        protected BooleanExpression provideAdditionalCheck(SendFirstValue sendFirstValue) {
            return SendThenDelegateProtocol.this.provideAdditionalCheck(commonInput, sendFirstValue);
        }
    }

    @Override
    public Representation compressTranscript(CommonInput commonInput, SigmaProtocolTranscript transcript) {
        SchnorrAnnouncement announcement = (SchnorrAnnouncement) transcript.getAnnouncement();
        return announcement.fragment.compressTranscript(announcement.fragmentAnnouncement, (ZnChallenge) transcript.getChallenge(), transcript.getResponse(), SchnorrVariableAssignment.EMPTY);
    }

    @Override
    public SigmaProtocolTranscript decompressTranscript(CommonInput commonInput, Challenge challenge, Representation compressedTranscript) throws IllegalArgumentException {
        TopLevelSchnorrFragment fragment = new TopLevelSchnorrFragment(commonInput);
        SigmaProtocolTranscript fragmentTranscript = fragment.decompressTranscript(compressedTranscript, (ZnChallenge) challenge, SchnorrVariableAssignment.EMPTY);
        return new SigmaProtocolTranscript(new SchnorrAnnouncement(fragment, fragmentTranscript.getAnnouncement()), challenge, fragmentTranscript.getResponse());
    }

    @Override
    public void debugProof(CommonInput commonInput, SecretInput secretInput) {
        new TopLevelSchnorrFragment(commonInput, secretInput).debugFragment(SchnorrVariableAssignment.EMPTY, getChallengeSpace(commonInput));
    }
}
