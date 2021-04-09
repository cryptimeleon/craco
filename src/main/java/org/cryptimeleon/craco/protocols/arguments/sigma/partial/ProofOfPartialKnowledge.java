package org.cryptimeleon.craco.protocols.arguments.sigma.partial;

import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.craco.protocols.arguments.sigma.*;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.SendFirstValue;
import org.cryptimeleon.math.expressions.bool.BooleanExpression;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.serialization.ListRepresentation;
import org.cryptimeleon.math.serialization.Representation;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public abstract class ProofOfPartialKnowledge implements SigmaProtocol {

    protected abstract ProtocolTree provideProtocolTree(CommonInput commonInput, SendFirstValue sendFirstValue);

    protected abstract ProverSpec provideProverSpec(CommonInput commonInput, SecretInput secretInput, ProverSpecBuilder builder);
    protected abstract SendFirstValue restoreSendFirstValue(CommonInput commonInput, Representation repr);
    protected abstract SendFirstValue simulateSendFirstValue(CommonInput commonInput);
    protected abstract BooleanExpression provideAdditionalCheck(CommonInput commonInput, SendFirstValue sendFirstValue);

    protected final ProtocolTree leaf(String name, SigmaProtocol protocol, CommonInput commonInput) {
        return new LeafNode(protocol, name, commonInput);
    }

    protected final ProtocolTree and(ProtocolTree protocol1, ProtocolTree protocol2) {
        return new AndNode(protocol1, protocol2);
    }

    protected final ProtocolTree or(ProtocolTree protocol1, ProtocolTree protocol2) {
        return new OrNode(protocol1, protocol2);
    }

    protected static abstract class ProtocolTree {
        protected final SigmaProtocol protocol;

        public ProtocolTree(SigmaProtocol protocol) {
            this.protocol = protocol;
        }

        protected abstract CommonInput getCommonInput();

        /**
         * Returns null if no valid secret input is known for this node.
         */
        protected abstract SecretInput getSecretInput(Function<String, ? extends SecretInput> secretInputsForLeafs);
    }

    private static class LeafNode extends ProtocolTree {
        public final String name;
        protected final CommonInput commonInput;

        public LeafNode(SigmaProtocol protocol, String name, CommonInput commonInput) {
            super(protocol);
            this.name = name;
            this.commonInput = commonInput;
        }

        @Override
        protected CommonInput getCommonInput() {
            return commonInput;
        }

        @Override
        protected SecretInput getSecretInput(Function<String, ? extends SecretInput> secretInputsForLeafs) {
            return secretInputsForLeafs.apply(name);
        }
    }

    private static class AndNode extends ProtocolTree {
        public final ProtocolTree lhs, rhs;

        public AndNode(ProtocolTree lhs, ProtocolTree rhs) {
            super(new AndProof(lhs.protocol, rhs.protocol));
            this.lhs = lhs;
            this.rhs = rhs;
        }

        @Override
        protected CommonInput getCommonInput() {
            return new CommonInput.CommonInputVector(lhs.getCommonInput(), rhs.getCommonInput());
        }

        @Override
        protected SecretInput getSecretInput(Function<String, ? extends SecretInput> secretInputsForLeafs) {
            SecretInput l = lhs.getSecretInput(secretInputsForLeafs);
            if (l == null)
                return null;
            SecretInput r = rhs.getSecretInput(secretInputsForLeafs);
            if (r == null)
                return null;

            return new SecretInput.SecretInputVector(l, r);
        }
    }

    private static class OrNode extends ProtocolTree {
        public final ProtocolTree lhs, rhs;

        public OrNode(ProtocolTree lhs, ProtocolTree rhs) {
            super(new OrProof(lhs.protocol, rhs.protocol));
            this.lhs = lhs;
            this.rhs = rhs;
        }

        @Override
        protected CommonInput getCommonInput() {
            return new CommonInput.CommonInputVector(lhs.getCommonInput(), rhs.getCommonInput());
        }

        @Override
        protected SecretInput getSecretInput(Function<String, ? extends SecretInput> secretInputsForLeafs) {
            SecretInput l = lhs.getSecretInput(secretInputsForLeafs);
            SecretInput r = rhs.getSecretInput(secretInputsForLeafs);
            if (l == null && r ==null)
                return null;

            return l == null ? new OrProof.OrProofSecretInput(r, true) : new OrProof.OrProofSecretInput(l, false);
        }
    }

    public static class ProverSpec {
        public final SendFirstValue sendFirstValue;
        public final Function<String, ? extends SecretInput> secretInputs;

        private ProverSpec(SendFirstValue sendFirstValue, Function<String, ? extends SecretInput> secretInputs) {
            this.sendFirstValue = sendFirstValue;
            this.secretInputs = secretInputs;
        }
    }

    public static class ProverSpecBuilder {
        private SendFirstValue sendFirstValue;
        private final Map<String, SecretInput> secretInputs = new HashMap<>();
        private boolean isBuilt = false;

        private ProverSpecBuilder() {

        }

        /**
         * Instructs the fragment to send the given value first to the verifier.
         */
        public void setSendFirstValue(SendFirstValue sendFirstValue) {
            if (this.sendFirstValue != null)
                throw new IllegalStateException("Cannot overwrite sendFirstValue");
            this.sendFirstValue = sendFirstValue;
        }

        /**
         * Registers the secret input for the protocol with the given name (same name as used in {@code leaf(...)} within the {@link #provideProtocolTree} call).
         * If you don't have a valid witness for some subprotocol, simply don't call this.
         *
         * @param protocolName the same name as used in {@code addVariable()}
         * @param secretInput a value that (hopefully) makes the subprotocol accept.
         */
        public void putSecretInput(String protocolName, SecretInput secretInput) {
            if (secretInputs.containsKey(protocolName))
                throw new IllegalArgumentException("Secret input for "+protocolName+" has already been set.");
            secretInputs.put(protocolName, secretInput);
        }

        public ProverSpec build() {
            if (isBuilt)
                throw new IllegalStateException("has already been built");
            isBuilt = true;
            if (sendFirstValue == null)
                throw new IllegalStateException("sendFirstValue is not set (use EmptySendFirstValue if you don't want any)");
            return new ProverSpec(sendFirstValue, secretInputs::get);
        }
    }

    private static class PartialKnowledgeAnnouncementSecret implements AnnouncementSecret {
        public final AnnouncementSecret protocolAnnouncementSecret;
        public final ProverSpec proverSpec;
        public final ProtocolTree protocolTree;
        public final CommonInput protocolCommonInput;
        public final SecretInput protocolSecretInput;
        public final Announcement protocolAnnouncement;

        public PartialKnowledgeAnnouncementSecret(AnnouncementSecret protocolAnnouncementSecret, ProverSpec proverSpec, ProtocolTree protocolTree, CommonInput protocolCommonInput, SecretInput protocolSecretInput, Announcement protocolAnnouncement) {
            this.protocolAnnouncementSecret = protocolAnnouncementSecret;
            this.proverSpec = proverSpec;
            this.protocolTree = protocolTree;
            this.protocolCommonInput = protocolCommonInput;
            this.protocolSecretInput = protocolSecretInput;
            this.protocolAnnouncement = protocolAnnouncement;
        }
    }

    private static class PartialKnowledgeAnnouncement implements Announcement {
        public final SendFirstValue sendFirstValue;
        public final Announcement protocolAnnouncement;
        public final ProtocolTree protocolTree;

        private PartialKnowledgeAnnouncement(SendFirstValue sendFirstValue, Announcement protocolAnnouncement, ProtocolTree protocolTree) {
            this.sendFirstValue = sendFirstValue;
            this.protocolAnnouncement = protocolAnnouncement;
            this.protocolTree = protocolTree;
        }

        @Override
        public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
            accumulator.escapeAndSeparate(sendFirstValue);
            accumulator.append(protocolAnnouncement);
            return accumulator;
        }

        @Override
        public Representation getRepresentation() {
            return new ListRepresentation(sendFirstValue.getRepresentation(), protocolAnnouncement.getRepresentation());
        }
    }

    @Override
    public AnnouncementSecret generateAnnouncementSecret(CommonInput commonInput, SecretInput secretInput) {
        ProverSpec proverSpec = provideProverSpec(commonInput, secretInput, new ProverSpecBuilder());
        ProtocolTree tree = provideProtocolTree(commonInput, proverSpec.sendFirstValue);
        CommonInput protocolCommonInput = tree.getCommonInput();
        SecretInput protocolSecretInput = tree.getSecretInput(proverSpec.secretInputs);
        AnnouncementSecret protocolAnnouncementSecret = tree.protocol.generateAnnouncementSecret(protocolCommonInput, protocolSecretInput);
        Announcement protocolAnnouncement = tree.protocol.generateAnnouncement(protocolCommonInput, protocolSecretInput, protocolAnnouncementSecret);
        return new PartialKnowledgeAnnouncementSecret(protocolAnnouncementSecret, proverSpec, tree, protocolCommonInput, protocolSecretInput, protocolAnnouncement);
    }

    @Override
    public Announcement generateAnnouncement(CommonInput commonInput, SecretInput secretInput, AnnouncementSecret announcementSecret) {
        return new PartialKnowledgeAnnouncement(
                ((PartialKnowledgeAnnouncementSecret) announcementSecret).proverSpec.sendFirstValue,
                ((PartialKnowledgeAnnouncementSecret) announcementSecret).protocolAnnouncement,
                ((PartialKnowledgeAnnouncementSecret) announcementSecret).protocolTree
                );
    }

    @Override
    public Response generateResponse(CommonInput commonInput, SecretInput secretInput, Announcement announcement, AnnouncementSecret announcementSecret, Challenge challenge) {
        PartialKnowledgeAnnouncementSecret announcementSecret1 = (PartialKnowledgeAnnouncementSecret) announcementSecret;
        return announcementSecret1.protocolTree.protocol.generateResponse(
                announcementSecret1.protocolCommonInput,
                announcementSecret1.protocolSecretInput,
                announcementSecret1.protocolAnnouncement,
                announcementSecret1.protocolAnnouncementSecret,
                challenge
        );
    }

    @Override
    public BooleanExpression checkTranscriptAsExpression(CommonInput commonInput, Announcement announcement, Challenge challenge, Response response) {
        SendFirstValue sendFirstValue = ((PartialKnowledgeAnnouncement) announcement).sendFirstValue;
        ProtocolTree tree = ((PartialKnowledgeAnnouncement) announcement).protocolTree;

        return provideAdditionalCheck(commonInput, sendFirstValue).and(
                tree.protocol.checkTranscriptAsExpression(tree.getCommonInput(), ((PartialKnowledgeAnnouncement) announcement).protocolAnnouncement, challenge, response)
        );
    }

    @Override
    public SigmaProtocolTranscript generateSimulatedTranscript(CommonInput commonInput, Challenge challenge) {
        SendFirstValue sendFirstValue = simulateSendFirstValue(commonInput);
        ProtocolTree tree = provideProtocolTree(commonInput, sendFirstValue);
        SigmaProtocolTranscript protocolTranscript = tree.protocol.generateSimulatedTranscript(tree.getCommonInput(), challenge);

        return new SigmaProtocolTranscript(
                new PartialKnowledgeAnnouncement(sendFirstValue, protocolTranscript.getAnnouncement(), tree),
                challenge,
                protocolTranscript.getResponse()
        );
    }

    @Override
    public Announcement restoreAnnouncement(CommonInput commonInput, Representation repr) {
        SendFirstValue sendFirstValue = restoreSendFirstValue(commonInput, repr.list().get(0));
        ProtocolTree tree = provideProtocolTree(commonInput, sendFirstValue);

        return new PartialKnowledgeAnnouncement(sendFirstValue, tree.protocol.restoreAnnouncement(tree.getCommonInput(), repr.list().get(1)), tree);
    }

    @Override
    public Response restoreResponse(CommonInput commonInput, Announcement announcement, Challenge challenge, Representation repr) {
        return ((PartialKnowledgeAnnouncement) announcement).protocolTree.protocol.restoreResponse(
                ((PartialKnowledgeAnnouncement) announcement).protocolTree.getCommonInput(),
                ((PartialKnowledgeAnnouncement) announcement).protocolAnnouncement,
                challenge,
                repr
        );
    }
}
