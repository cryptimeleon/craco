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

/**
 * A Sigma Protocol that composes several subprotocols in any AND/OR tree structure [CDS94].
 * <br>
 * To use this class, extend it and implement its abstract methods as documented. <br>
 * The general flow of this protocol is that first the prover generates some {@link SendFirstValue} (e.g., a Pedersen commitment to some values) that is sent alongside the first message of this Sigma protocol.
 * From this {@link SendFirstValue}, prover and verifier set up the appropriate subprotocols and tree structure (similarly to {@link org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.SendThenDelegateFragment}).
 * Then those subprotocols are run in a way that respects the desired AND/OR compositions.
 *
 * <p>
 * [CDS94] Cramer, Ronald, Ivan Damgård, and Berry Schoenmakers. "Proofs of partial knowledge and simplified design of witness hiding protocols". CRYPTO 1994
 * </p>
 */
public abstract class ProofOfPartialKnowledge implements SigmaProtocol {
    /**
     * Sets up the desired subprotocols and returns the {@link ProtocolTree} that encodes the AND/OR relations between them.
     *
     * Implementors should build the {@link ProtocolTree} using {@link #leaf}, {@link #and}, and {@link #or}.
     *
     * @param commonInput the public input to this ProofOfPartialKnowledge (can be anything appropriate for the concrete protocol implemented).
     * @param sendFirstValue the value sent by the prover before the subprotocols start running.
     * @return a tree of subprotocols that defines what subprotocols are composed in what way.
     */
    protected abstract ProtocolTree provideProtocolTree(CommonInput commonInput, SendFirstValue sendFirstValue);

    /**
     * Sets up the {@link ProverSpec}.
     * <br>
     * Implementors shall use the provided builder to set up <br>
     * <ol>
     *     <li>the {@link SendFirstValue} the prover wants to send (can be {@link org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.SendFirstValue.EmptySendFirstValue}.</li>
     *     <li>
     *         the witnesses to use for the subprotocols. If for some subprotocol you don't have a witness, simply don't call {@link ProverSpecBuilder#putSecretInput(String, SecretInput)} for it.
     *         <br>Obviously, you'll have to provide sufficiently many witnesses for subprotocols to satisfy the AND/OR connections of subprotocols encoded in the tree returned by {@link #provideProtocolTree(CommonInput, SendFirstValue)}.
     *     </li>
     * </ol>
     *
     * @param commonInput the public input to this ProofOfPartialKnowledge (can be anything appropriate for the concrete protocol implemented).
     * @param secretInput the secret input to this ProofOfPartialKnowledge (can be anything appropriate for the concrete protocol implemented).
     * @param builder an object to use to build the {@link ProverSpec}.
     * @return a prover spec returned by the {@code builder}.
     */
    protected abstract ProverSpec provideProverSpec(CommonInput commonInput, SecretInput secretInput, ProverSpecBuilder builder);

    /**
     * Restores a {@link SendFirstValue} from representation.
     */
    protected abstract SendFirstValue restoreSendFirstValue(CommonInput commonInput, Representation repr);

    /**
     * Simulates the {@link SendFirstValue}, i.e. returns one with a distribution that indistinguishable from an honest prover's.
     */
    protected abstract SendFirstValue simulateSendFirstValue(CommonInput commonInput);

    /**
     * Returns true if the given sendFirstValue is well-formed and valid. If the returned expression evaluates to false, the transcript containing SendFirstValue will be rejected by the verifier.
     * Typical examples of such checks would be something like "the sent group element must not be the neutral element".
     * <br>
     * The implementation for this can simply be {@code return BooleanExpression.TRUE} if no additional checks are needed.
     */
    protected abstract BooleanExpression provideAdditionalCheck(CommonInput commonInput, SendFirstValue sendFirstValue);

    /**
     * Construct a tree that contains a single subprotocol to run.
     * @param name name of the protocol (must be unique, i.e. don't call leaf() twice with the same name in the same execution of {@link #provideProtocolTree}).
     * @param protocol the subprotocol
     * @param commonInput the common input for the subprotocol.
     */
    protected final ProtocolTree leaf(String name, SigmaProtocol protocol, CommonInput commonInput) {
        return new LeafNode(protocol, name, commonInput);
    }

    /**
     * Construct a tree that AND-combines two subtrees.
     */
    protected final ProtocolTree and(ProtocolTree protocol1, ProtocolTree protocol2) {
        return new AndNode(protocol1, protocol2);
    }

    /**
     * Construct a tree that OR-combines two subtrees.
     */
    protected final ProtocolTree or(ProtocolTree protocol1, ProtocolTree protocol2) {
        return new OrNode(protocol1, protocol2);
    }

    /**
     * To build, use {@link #leaf}, {@link #and}, and {@link #or}.
     */
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
                return null; //cannot satisfy this node
            SecretInput r = rhs.getSecretInput(secretInputsForLeafs);
            if (r == null)
                return null; //cannot satisfy this node

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
                return null; //cannot satisfy this node

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
