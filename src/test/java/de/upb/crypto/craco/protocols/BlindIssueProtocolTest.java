package de.upb.crypto.craco.protocols;

import de.upb.crypto.craco.commitment.interfaces.CommitmentScheme;
import de.upb.crypto.craco.protocols.arguments.damgardtechnique.DamgardTechnique;
import de.upb.crypto.craco.protocols.arguments.sigma.instance.SigmaProtocolInstance;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.DelegateProtocol;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.LinearStatementFragment;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.SendThenDelegateFragment;
import de.upb.crypto.craco.protocols.base.BaseProtocol;
import de.upb.crypto.craco.protocols.base.BaseProtocolInstance;
import de.upb.crypto.math.expressions.exponent.ExponentExpr;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.pairings.counting.CountingBilinearGroup;
import de.upb.crypto.math.pairings.generic.BilinearGroup;
import de.upb.crypto.math.pairings.type3.bn.BarretoNaehrigBilinearGroup;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.cartesian.ExponentExpressionVector;
import de.upb.crypto.math.structures.cartesian.GroupElementVector;
import de.upb.crypto.math.structures.cartesian.RingElementVector;
import de.upb.crypto.math.structures.zn.Zn;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BlindIssueProtocolTest {

    @Test
    public void test() {
        BilinearGroup group = new CountingBilinearGroup(128, BilinearGroup.Type.TYPE_3);
        Zn zn = group.getZn();

        //Generate PS secret key
        Zn.ZnElement x = group.getZn().getUniformlyRandomElement();
        RingElementVector y = group.getZn().getUniformlyRandomElements(6);
        IssuerInput issuerInput = new IssuerInput(x);

        //Generate public key
        GroupElement g = group.getG1().getUniformlyRandomElement().precomputePow();
        GroupElement tildeg = group.getG2().getUniformlyRandomElement().precomputePow();
        GroupElement tildeX = tildeg.pow(x).precomputePow();
        GroupElementVector tildeY = tildeg.pow(y).precomputePow();
        GroupElementVector Y = g.pow(y);
        BlindIssueCommonInput commonInput = new BlindIssueCommonInput(group, g, Y, tildeg, tildeX, tildeY);

        //Set up secret message for receiver
        RingElementVector message = new RingElementVector(zn.valueOf(4), zn.valueOf(8), zn.valueOf(15), zn.valueOf(16), zn.valueOf(23), zn.valueOf(42));
        ReceiverInput receiverInput = new ReceiverInput(message);

        //Set up and run protocol
        BlindIssueProtocol protocol = new BlindIssueProtocol(group);
        BlindIssueProtocolInstance receiverInstance = protocol.instantiateProtocol("receiver", commonInput, receiverInput);
        BlindIssueProtocolInstance issuerInstance = protocol.instantiateProtocol("issuer", commonInput, issuerInput);

        assertTrue(receiverInstance.sendsFirstMessage());

        BlindIssueProtocolInstance instanceWhosTurnItIs = receiverInstance;
        Representation messageInTransit = null;
        while (!receiverInstance.hasTerminated()) {
            messageInTransit = instanceWhosTurnItIs.nextMessage(messageInTransit);
            instanceWhosTurnItIs = instanceWhosTurnItIs == receiverInstance ? issuerInstance : receiverInstance;
        }

        //Check signature
        GroupElement sigma0 = receiverInstance.getSigma0();
        GroupElement sigma1 = receiverInstance.getSigma1();
        assertEquals(group.getBilinearMap().apply(sigma0, tildeX.op(tildeY.innerProduct(message))), group.getBilinearMap().apply(sigma1, tildeg));
    }

    public static class IssuerInput implements SecretInput {
        public final Zn.ZnElement x;

        public IssuerInput(Zn.ZnElement x) {
            this.x = x;
        }
    }

    public static class ReceiverInput implements SecretInput {
        public final RingElementVector message;

        public ReceiverInput(RingElementVector message) {
            this.message = message;
        }
    }

    public static class BlindIssueCommonInput implements CommonInput {
        public final BilinearGroup group;
        public final GroupElement g;
        public final GroupElementVector Y;
        public final GroupElement tildeg;
        public final GroupElement tildeX;
        public final GroupElementVector tildeY;

        public BlindIssueCommonInput(BilinearGroup group, GroupElement g, GroupElementVector Y, GroupElement tildeg, GroupElement tildeX, GroupElementVector tildeY) {
            this.group = group;
            this.g = g;
            this.Y = Y;
            this.tildeg = tildeg;
            this.tildeX = tildeX;
            this.tildeY = tildeY;
        }
    }

    public static class BlindIssueProtocol extends BaseProtocol {
        //Subprotocol needs
        protected CommitmentScheme commitmentSchemeForDamgard;

        public BlindIssueProtocol(BilinearGroup group) {
            super("receiver", "issuer");
            commitmentSchemeForDamgard = DamgardTechnique.generateCommitmentScheme(group.getG1());
        }

        @Override
        public BlindIssueProtocolInstance instantiateProtocol(String role, CommonInput commonInput, SecretInput secretInput) {
            return new BlindIssueProtocolInstance(this, role, (BlindIssueCommonInput) commonInput, secretInput);
        }
    }

    public static class BlindIssueProtocolInstance extends BaseProtocolInstance {
        //Input
        private final BilinearGroup group;
        private final Zn zn;
        private final BlindIssueCommonInput commonInput;
        private final ReceiverInput receiverInput;
        private final IssuerInput issuerInput;

        private final BlindIssueProtocol protocol;

        //Protocol state
        private GroupElement commitment;
        private Zn.ZnElement blindingFactor;
        private GroupElement sigma0, sigma1;
        private SigmaProtocolInstance openingProofInstance;

        public BlindIssueProtocolInstance(BlindIssueProtocol protocol, String role, BlindIssueCommonInput commonInput, SecretInput secretInput) {
            super(protocol, role);
            this.protocol = protocol;
            this.commonInput = commonInput;
            this.group = commonInput.group;
            this.zn = group.getZn();

            this.receiverInput = role.equals("receiver") ? (ReceiverInput) secretInput : null;
            this.issuerInput = role.equals("issuer") ? (IssuerInput) secretInput : null;
        }

        @Override
        protected void doRoundForFirstRole(int round) {
            switch (round) {
                case 0:
                    //Commit to desired messages
                    blindingFactor = zn.getUniformlyRandomElement();
                    commitment = commonInput.Y.innerProduct(receiverInput.message).op(commonInput.g.pow(blindingFactor)); //g^{\sum y_i * m_i + blindingFactor}

                    //Send commitment
                    send("commitment", commitment.getRepresentation());

                    //Prove you can open commitment
                    runSubprotocolConcurrently("openingProof", openingProofInstance = new DamgardTechnique(new OpeningProof(), protocol.commitmentSchemeForDamgard).getProverInstance(new OpeningCommonInput(commitment), new OpeningSecretInput(receiverInput.message, blindingFactor)));
                    break;
                case 2:
                    //Wait for subprotocol to finish (internally, the sigma protocol's response is sent)
                    break;
                case 4:
                    //Receive blinded signature, unblind, finish
                    sigma0 = group.getG1().getElement(receive("sigma0")); //h
                    sigma1 = group.getG1().getElement(receive("blindedSigma1")).op(sigma0.pow(blindingFactor.neg())); //h^{x + \sum y_i * m_i}
                    terminate();
                    break;
            }
        }

        @Override
        protected void doRoundForSecondRole(int round) {
            switch (round) {
                case 1:
                    //Receive commitment, run subprotocol as verifier (internally sends Sigma protocol challenge this round)
                    commitment = group.getG1().getElement(receive("commitment"));
                    runSubprotocolConcurrently("openingProof", openingProofInstance = new DamgardTechnique(new OpeningProof(), protocol.commitmentSchemeForDamgard).getVerifierInstance(new OpeningCommonInput(commitment)));
                    break;
                case 3:
                    //Check proof, sign committed value
                    if (openingProofInstance.isAccepting()) {
                        Zn.ZnElement r = zn.getUniformlyRandomNonzeroElement();
                        sigma0 = commonInput.g.pow(r);
                        send("sigma0", sigma0.getRepresentation()); //g^r
                        send("blindedSigma1", commitment.op(commonInput.g.pow(issuerInput.x)).pow(r).getRepresentation()); //g^{r * (x + \sum y_i m_i)} * g^{r*blindingFactor}
                    } else {
                        throw new IllegalStateException("Proof was not accepted");
                    }
                    terminate();
                    break;
            }
        }

        public GroupElement getSigma0() {
            return sigma0;
        }

        public GroupElement getSigma1() {
            return sigma1;
        }


        public class OpeningProof extends DelegateProtocol {

            @Override
            protected SendThenDelegateFragment.ProverSpec provideProverSpecWithNoSendFirst(CommonInput commonInput, SecretInput secretInput1, SendThenDelegateFragment.ProverSpecBuilder builder) {
                OpeningSecretInput secretInput = (OpeningSecretInput) secretInput1;
                secretInput.message.forEach((i, m) -> builder.putWitnessValue("m"+i, (Zn.ZnElement) m));
                builder.putWitnessValue("blindingFactor", secretInput.blindingFactor);

                return builder.build();
            }

            @Override
            protected SendThenDelegateFragment.SubprotocolSpec provideSubprotocolSpec(CommonInput commonInput, SendThenDelegateFragment.SubprotocolSpecBuilder builder) {
                ExponentExpressionVector msgVars = BlindIssueProtocolInstance.this.commonInput.Y.map((i, m) -> builder.addZnVariable("m"+i, zn), ExponentExpressionVector::new);
                ExponentExpr blindVar = builder.addZnVariable("blindingFactor", zn);

                builder.addSubprotocol("schnorr", new LinearStatementFragment(
                        BlindIssueProtocolInstance.this.commonInput.Y.expr().innerProduct(msgVars).op(BlindIssueProtocolInstance.this.commonInput.g.pow(blindVar)).isEqualTo(((OpeningCommonInput) commonInput).commitment)
                ));

                return builder.build();
            }

            @Override
            public BigInteger getChallengeSpaceSize() {
                return BlindIssueProtocolInstance.this.commonInput.group.getG1().size();
            }
        }

        public static class OpeningCommonInput implements CommonInput {
            public final GroupElement commitment;

            public OpeningCommonInput(GroupElement commitment) {
                this.commitment = commitment;
            }
        }

        public static class OpeningSecretInput implements SecretInput {
            public final RingElementVector message;
            public final Zn.ZnElement blindingFactor;

            public OpeningSecretInput(RingElementVector message, Zn.ZnElement blindingFactor) {
                this.message = message;
                this.blindingFactor = blindingFactor;
            }
        }
    }
}
