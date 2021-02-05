package de.upb.crypto.craco.protocols.arguments.sigma.schnorr;

import de.upb.crypto.craco.protocols.CommonInput;
import de.upb.crypto.craco.protocols.SecretInput;
import de.upb.crypto.craco.protocols.arguments.sigma.*;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.variables.SchnorrVariableAssignment;
import de.upb.crypto.math.expressions.bool.BooleanExpression;
import de.upb.crypto.math.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.ListRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.math.BigInteger;

/**
 * <p>The protocol version of {@link SendThenDelegateFragment}.</p>
 * <p>
 *     A {@link SchnorrFragment} is always incomplete in the sense that it depends on external variables.
 *     In contrast, a {@link SigmaProtocol} has no external dependencies and, hence, can be run standalone.
 * </p>
 * <p>
 *     An implementation of a {@link SendThenDelegateProtocol} is very similar to an implementation of
 *     a {@link SendThenDelegateFragment}, except that there are no external {@link de.upb.crypto.craco.protocols.arguments.sigma.schnorr.variables.SchnorrVariable}s and the protocol
 *     must define all its variables itself.
 * </p>
 */
public abstract class SendThenDelegateProtocol implements SigmaProtocol {

    /**
     * Run by the prover to set up (1) the sendFirstValue and
     * (2) witness values for variables this fragment proves knowledge of itself (i.e. those specified in {@link SendThenDelegateProtocol#provideSubprotocolSpec(CommonInput, SendThenDelegateFragment.SendFirstValue, SendThenDelegateFragment.SubprotocolSpecBuilder)}).
     *
     * @see SendThenDelegateFragment#provideProverSpec(SchnorrVariableAssignment, SendThenDelegateFragment.ProverSpecBuilder)
     */
    protected abstract SendThenDelegateFragment.ProverSpec provideProverSpec(CommonInput commonInput, SecretInput secretInput, SendThenDelegateFragment.ProverSpecBuilder builder);
    protected abstract SendThenDelegateFragment.SendFirstValue recreateSendFirstValue(CommonInput commonInput, Representation repr);

    /**
     * @see SendThenDelegateFragment#simulateSendFirstValue()
     */
    protected abstract SendThenDelegateFragment.SendFirstValue simulateSendFirstValue(CommonInput commonInput);

    /**
     * @see SendThenDelegateFragment#provideProverSpec(SchnorrVariableAssignment, SendThenDelegateFragment.ProverSpecBuilder)
     */
    protected abstract SendThenDelegateFragment.SubprotocolSpec provideSubprotocolSpec(CommonInput commonInput, SendThenDelegateFragment.SendFirstValue sendFirstValue, SendThenDelegateFragment.SubprotocolSpecBuilder builder);

    /**
     * @see SendThenDelegateFragment#provideAdditionalCheck(SendThenDelegateFragment.SendFirstValue)
     */
    protected abstract BooleanExpression provideAdditionalCheck(CommonInput commonInput, SendThenDelegateFragment.SendFirstValue sendFirstValue);

    @Override
    public abstract BigInteger getChallengeSpaceSize();

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
    public SchnorrChallenge generateChallenge(CommonInput commonInput) {
        return SchnorrChallenge.random(getChallengeSpaceSize());
    }

    @Override
    public Challenge createChallengeFromBytes(CommonInput commonInput, byte[] bytes) {
        return new SchnorrChallenge(new BigInteger(1, bytes));
    }

    @Override
    public Response generateResponse(CommonInput commonInput, SecretInput secretInput, Announcement announcement, AnnouncementSecret announcementSecret, Challenge challenge) {
        SchnorrAnnouncementSecret announcementSecret1 = (SchnorrAnnouncementSecret) announcementSecret;
        return announcementSecret1.fragment.generateResponse(SchnorrVariableAssignment.EMPTY, announcementSecret1.fragmentAnnouncementSecret, (SchnorrChallenge) challenge);
    }

    @Override
    public BooleanExpression checkTranscriptAsExpression(CommonInput commonInput, Announcement announcement, Challenge challenge, Response response) {
        return ((SchnorrAnnouncement) announcement).fragment.checkTranscript(((SchnorrAnnouncement) announcement).fragmentAnnouncement, (SchnorrChallenge) challenge, response, SchnorrVariableAssignment.EMPTY);
    }

    @Override
    public SigmaProtocolTranscript generateSimulatedTranscript(CommonInput commonInput, Challenge challenge) {
        TopLevelSchnorrFragment fragment = new TopLevelSchnorrFragment(commonInput);
        return fragment.generateSimulatedTranscript((SchnorrChallenge) challenge, SchnorrVariableAssignment.EMPTY);
    }

    @Override
    public Announcement recreateAnnouncement(CommonInput commonInput, Representation repr) {
        TopLevelSchnorrFragment fragment = new TopLevelSchnorrFragment(commonInput);
        return new SchnorrAnnouncement(fragment, fragment.recreateAnnouncement(repr));
    }

    @Override
    public Challenge recreateChallenge(CommonInput commonInput, Representation repr) {
        return new SchnorrChallenge(repr);
    }

    @Override
    public Response recreateResponse(CommonInput commonInput, Announcement announcement, Challenge challenge, Representation repr) {
        return ((SchnorrAnnouncement) announcement).fragment.recreateResponse(((SchnorrAnnouncement) announcement).fragmentAnnouncement, repr);
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
        protected SendFirstValue recreateSendFirstValue(Representation repr) {
            return SendThenDelegateProtocol.this.recreateSendFirstValue(commonInput, repr);
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
        return announcement.fragment.compressTranscript(announcement.fragmentAnnouncement, (SchnorrChallenge) transcript.getChallenge(), transcript.getResponse(), SchnorrVariableAssignment.EMPTY);
    }

    @Override
    public SigmaProtocolTranscript decompressTranscript(CommonInput commonInput, Challenge challenge, Representation compressedTranscript) throws IllegalArgumentException {
        TopLevelSchnorrFragment fragment = new TopLevelSchnorrFragment(commonInput);
        SigmaProtocolTranscript fragmentTranscript = fragment.decompressTranscript(compressedTranscript, (SchnorrChallenge) challenge, SchnorrVariableAssignment.EMPTY);
        return new SigmaProtocolTranscript(new SchnorrAnnouncement(fragment, fragmentTranscript.getAnnouncement()), challenge, fragmentTranscript.getResponse());
    }
}
