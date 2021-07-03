package org.cryptimeleon.craco.protocols.arguments.sigma.partial;

import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.craco.protocols.arguments.sigma.*;
import org.cryptimeleon.math.expressions.bool.BooleanExpression;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.serialization.ListRepresentation;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.cartesian.Vector;

import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

/**
 * The OR composition of two SigmaProtocols.
 * Meaning that in order to run this protocol, the prover must have knowledge of valid secret input for one of the two (sub)protocols.
 * <br>
 * To use:
 * <ol>
 * <li>Instantiate this protocol with the two protocols to compose.</li>
 * <li>The common input for this protocol is a {@link org.cryptimeleon.craco.protocols.CommonInput.CommonInputVector} of the subprotocols' common inputs</li>
 * <li>The secret input for this protocol is a {@link OrProofSecretInput} (which encapsulates a witness for either the first or the second protocol)</li>
 * </ol>
 *
 * Depending on your use-case, {@link ProofOfPartialKnowledge} may be more convenient for you.
 */
public class OrProof implements SigmaProtocol {
    public final SigmaProtocol protocol0, protocol1;

    public OrProof(SigmaProtocol protocol0, SigmaProtocol protocol1) {
        this.protocol0 = protocol0;
        this.protocol1 = protocol1;
    }

    public static class OrProofSecretInput implements SecretInput {
        public final SecretInput secretInput;
        public final boolean isForProtocol1;

        public OrProofSecretInput(SecretInput secretInput, boolean isForProtocol1) {
            this.secretInput = secretInput;
            this.isForProtocol1 = isForProtocol1;
        }
    }

    protected static class OrProofResponse implements Response {
        public final Response response0, response1;
        public final Challenge challenge0;

        public OrProofResponse(Response response0, Response response1, Challenge challenge0) {
            this.response0 = response0;
            this.response1 = response1;
            this.challenge0 = challenge0;
        }

        public OrProofResponse(ResponseVector responses, Challenge challenge0) {
            this(responses.get(0), responses.get(1), challenge0);
        }

        @Override
        public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
            accumulator.escapeAndSeparate(response0);
            accumulator.escapeAndSeparate(response1);
            accumulator.escapeAndSeparate(challenge0);
            return accumulator;
        }

        @Override
        public Representation getRepresentation() {
            return new ListRepresentation(response0.getRepresentation(), response1.getRepresentation(), challenge0.getRepresentation());
        }
    }

    private static class OrProofAnnouncementSecret implements AnnouncementSecret {
        public final AnnouncementSecret announcementSecret;
        public final Announcement announcement;
        public final SigmaProtocolTranscript simulatedTranscript;

        public OrProofAnnouncementSecret(AnnouncementSecret announcementSecret, Announcement announcement, SigmaProtocolTranscript simulatedTranscript) {
            this.announcementSecret = announcementSecret;
            this.announcement = announcement;
            this.simulatedTranscript = simulatedTranscript;
        }
    }

    private <T> T getSimulated(SecretInput secretInput, T protocol0, T protocol1) {
        return ((OrProofSecretInput) secretInput).isForProtocol1 ? protocol0: protocol1;
    }

    private <T> T getHonest(SecretInput secretInput, T protocol0, T protocol1) {
        return ((OrProofSecretInput) secretInput).isForProtocol1 ? protocol1: protocol0;
    }

    private <T> T getHonest(SecretInput secretInput, Vector<T> vector) {
        return ((OrProofSecretInput) secretInput).isForProtocol1 ? vector.get(1): vector.get(0);
    }

    private <T> T getSimulated(SecretInput secretInput, Vector<T> vector) {
        return ((OrProofSecretInput) secretInput).isForProtocol1 ? vector.get(0): vector.get(1);
    }

    private <T> T getProtocol0(SecretInput secretInput, T honest, T simulated) {
        return ((OrProofSecretInput) secretInput).isForProtocol1 ? simulated : honest;
    }

    private <T> T getProtocol1(SecretInput secretInput, T honest, T simulated) {
        return ((OrProofSecretInput) secretInput).isForProtocol1 ? honest : simulated;
    }

    private <T, Y extends Vector<? extends T>> Y getVector(SecretInput secretInput, T honest, T simulated, Function<List<? extends T>, Y> constructor) {
        return ((OrProofSecretInput) secretInput).isForProtocol1 ? constructor.apply(Arrays.asList(simulated, honest)) : constructor.apply(Arrays.asList(honest, simulated));
    }

    @Override
    public AnnouncementSecret generateAnnouncementSecret(CommonInput commonInput, SecretInput secretInput) {
        SigmaProtocol simulationProtocol = getSimulated(secretInput, protocol0, protocol1);
        SigmaProtocol honestProtocol = getHonest(secretInput, protocol0, protocol1);

        CommonInput simulationProtocolCommonInput = getSimulated(secretInput, (CommonInput.CommonInputVector) commonInput);
        CommonInput honestProtocolCommonInput = getHonest(secretInput, (CommonInput.CommonInputVector) commonInput);

        //Simulate protocol for which we have no witness
        SigmaProtocolTranscript simulatedTranscript = simulationProtocol.generateSimulatedTranscript(simulationProtocolCommonInput, simulationProtocol.generateChallenge(simulationProtocolCommonInput));

        //Generate honest announcement secret for the other protocol
        AnnouncementSecret announcementSecret = honestProtocol.generateAnnouncementSecret(honestProtocolCommonInput, ((OrProofSecretInput) secretInput).secretInput);
        Announcement announcement = honestProtocol.generateAnnouncement(honestProtocolCommonInput, ((OrProofSecretInput) secretInput).secretInput, announcementSecret);

        return new OrProofAnnouncementSecret(announcementSecret, announcement, simulatedTranscript);
    }

    @Override
    public Announcement generateAnnouncement(CommonInput commonInput, SecretInput secretInput, AnnouncementSecret announcementSecret) {
        Announcement simulatedAnnouncement = ((OrProofAnnouncementSecret) announcementSecret).simulatedTranscript.getAnnouncement();
        Announcement honestAnnouncement = ((OrProofAnnouncementSecret) announcementSecret).announcement;
        return getVector(secretInput, honestAnnouncement, simulatedAnnouncement, Announcement.AnnouncementVector::new);
    }

    @Override
    public ChallengeSpace getChallengeSpace(CommonInput commonInput) {
        ChallengeSpace challengeSpace = protocol0.getChallengeSpace(((CommonInput.CommonInputVector) commonInput).get(0));
        if (!protocol1.getChallengeSpace(((CommonInput.CommonInputVector) commonInput).get(1)).equals(challengeSpace))
            throw new IllegalStateException("Challenge spaces of subprotocols inconsistent.");
        return challengeSpace;
    }

    @Override
    public Response generateResponse(CommonInput commonInput, SecretInput secretInput, Announcement announcement, AnnouncementSecret announcementSecret, Challenge challenge) {
        ChallengeSpace challengeSpace = getChallengeSpace(commonInput);
        Challenge honestChallenge = challengeSpace.subtract(challenge, ((OrProofAnnouncementSecret) announcementSecret).simulatedTranscript.getChallenge());
        Response honestResponse = getHonest(secretInput, protocol0, protocol1).generateResponse(
                getHonest(secretInput, ((CommonInput.CommonInputVector) commonInput)),
                ((OrProofSecretInput) secretInput).secretInput,
                ((OrProofAnnouncementSecret) announcementSecret).announcement,
                ((OrProofAnnouncementSecret) announcementSecret).announcementSecret,
                honestChallenge
                );
        return new OrProofResponse(getVector(secretInput, honestResponse, ((OrProofAnnouncementSecret) announcementSecret).simulatedTranscript.getResponse(), Response.ResponseVector::new),
                getProtocol0(secretInput, honestChallenge, ((OrProofAnnouncementSecret) announcementSecret).simulatedTranscript.getChallenge()));
    }

    @Override
    public BooleanExpression checkTranscriptAsExpression(CommonInput commonInput, Announcement announcement, Challenge challenge, Response response) {
        Challenge challenge0 = ((OrProofResponse) response).challenge0;
        Challenge challenge1 = getChallengeSpace(commonInput).subtract(challenge, challenge0);

        return protocol0.checkTranscriptAsExpression(((CommonInput.CommonInputVector) commonInput).get(0),
                ((Announcement.AnnouncementVector) announcement).get(0),
                challenge0,
                ((OrProofResponse) response).response0).and(
                protocol1.checkTranscriptAsExpression(((CommonInput.CommonInputVector) commonInput).get(1),
                        ((Announcement.AnnouncementVector) announcement).get(1),
                        challenge1,
                        ((OrProofResponse) response).response1)
        );
    }

    @Override
    public SigmaProtocolTranscript generateSimulatedTranscript(CommonInput commonInput, Challenge challenge) {
        ChallengeSpace challengeSpace = getChallengeSpace(commonInput);
        Challenge challenge0 = challengeSpace.generateRandomChallenge();
        Challenge challenge1 = challengeSpace.subtract(challenge, challenge0);

        SigmaProtocolTranscript transcript0 = protocol0.generateSimulatedTranscript(((CommonInput.CommonInputVector) commonInput).get(0), challenge0);
        SigmaProtocolTranscript transcript1 = protocol1.generateSimulatedTranscript(((CommonInput.CommonInputVector) commonInput).get(1), challenge1);

        return new SigmaProtocolTranscript(
                new Announcement.AnnouncementVector(transcript0.getAnnouncement(), transcript1.getAnnouncement()),
                challenge,
                new OrProofResponse(transcript0.getResponse(), transcript1.getResponse(), challenge0)
        );
    }

    @Override
    public Announcement restoreAnnouncement(CommonInput commonInput, Representation repr) {
        return Vector.of(protocol0, protocol1)
                .map((i, protocol) -> protocol.restoreAnnouncement(((CommonInput.CommonInputVector) commonInput).get(i), repr.list().get(i)), Announcement.AnnouncementVector::new);
    }

    @Override
    public Response restoreResponse(CommonInput commonInput, Announcement announcement, Challenge challenge, Representation repr) {
        ChallengeSpace challengeSpace = getChallengeSpace(commonInput);
        Challenge challenge0 = challengeSpace.restoreChallenge(repr.list().get(2));
        Challenge challenge1 = challengeSpace.subtract(challenge, challenge0);
        Response.ResponseVector responses = Vector.of(protocol0, protocol1)
                .map((i, protocol) -> protocol.restoreResponse(
                        ((CommonInput.CommonInputVector) commonInput).get(i),
                        ((Announcement.AnnouncementVector) announcement).get(i),
                        i == 0 ? challenge0 : challenge1,
                        repr.list().get(i)), Response.ResponseVector::new);
        return new OrProofResponse(responses, challenge0);
    }

    @Override
    public void debugProof(CommonInput commonInput, SecretInput secretInput) {
        try {
            if (((OrProofSecretInput) secretInput).isForProtocol1)
                protocol1.debugProof(((CommonInput.CommonInputVector) commonInput).get(1), ((OrProofSecretInput) secretInput).secretInput);
            else
                protocol0.debugProof(((CommonInput.CommonInputVector) commonInput).get(0), ((OrProofSecretInput) secretInput).secretInput);
        } catch (RuntimeException e) {
            throw new RuntimeException("OR proof "+(((OrProofSecretInput) secretInput).isForProtocol1 ? "right" : "left") + " child threw error (other child wasn't asked)");
        }
    }
}
