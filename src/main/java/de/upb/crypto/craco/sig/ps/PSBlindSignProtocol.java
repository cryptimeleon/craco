package de.upb.crypto.craco.sig.ps;

import de.upb.crypto.craco.commitment.CommitmentScheme;
import de.upb.crypto.craco.common.plaintexts.MessageBlock;
import de.upb.crypto.craco.common.plaintexts.RingElementPlainText;
import de.upb.crypto.craco.protocols.CommonInput;
import de.upb.crypto.craco.protocols.SecretInput;
import de.upb.crypto.craco.protocols.arguments.damgardtechnique.DamgardTechnique;
import de.upb.crypto.craco.protocols.arguments.sigma.instance.SigmaProtocolInstance;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.DelegateProtocol;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.LinearStatementFragment;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.SendThenDelegateFragment;
import de.upb.crypto.craco.protocols.base.BaseProtocol;
import de.upb.crypto.craco.protocols.base.BaseProtocolInstance;
import de.upb.crypto.math.expressions.exponent.ExponentExpr;
import de.upb.crypto.math.structures.cartesian.ExponentExpressionVector;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.structures.groups.cartesian.GroupElementVector;
import de.upb.crypto.math.structures.groups.elliptic.BilinearGroup;
import de.upb.crypto.math.structures.rings.RingElement;
import de.upb.crypto.math.structures.rings.cartesian.RingElementVector;
import de.upb.crypto.math.structures.rings.zn.Zn;

import java.math.BigInteger;

public class PSBlindSignProtocol extends BaseProtocol {
    protected final CommitmentScheme commitmentSchemeForDamgard;
    protected final PSExtendedSignatureScheme scheme;

    public PSBlindSignProtocol(PSExtendedSignatureScheme scheme, CommitmentScheme commitmentSchemeForDamgard) {
        super("receiver", "signer");
        this.commitmentSchemeForDamgard = commitmentSchemeForDamgard;
        this.scheme = scheme;
    }

    public static CommitmentScheme generatePp(PSExtendedSignatureScheme scheme) {
        return DamgardTechnique.generateCommitmentScheme(scheme.pp.getBilinearGroup().getG1());
    }

    @Override
    public BlindSignProtocolInstance instantiateProtocol(String role, CommonInput commonInput, SecretInput secretInput) {
        return new BlindSignProtocolInstance(this, role, (PSExtendedVerificationKey) commonInput, secretInput);
    }

    public BlindSignProtocolInstance instantiateProtocolForSigner(PSExtendedVerificationKey commonInput, PSSigningKey secretInput) {
        return instantiateProtocol("signer", commonInput, secretInput);
    }

    public BlindSignProtocolInstance instantiateProtocolForReceiver(PSExtendedVerificationKey commonInput, ReceiverInput secretInput) {
        return instantiateProtocol("receiver", commonInput, secretInput);
    }

    public static class ReceiverInput implements SecretInput {
        public final RingElementVector message;

        public ReceiverInput(RingElementVector message) {
            this.message = message;
        }

        public ReceiverInput(MessageBlock message) {
            this(message.<RingElement, RingElementVector>map(pt -> ((RingElementPlainText) pt).getRingElement(), RingElementVector::new));
        }
    }


    public static class BlindSignProtocolInstance extends BaseProtocolInstance {
        //Input
        private final BilinearGroup group;
        private final Zn zn;
        private final PSExtendedVerificationKey commonInput;
        private final ReceiverInput receiverInput;
        private final PSSigningKey signerInput;

        private final PSBlindSignProtocol protocol;

        //Protocol state
        private GroupElement commitment;
        private Zn.ZnElement blindingFactor;
        private PSSignature resultSignature;
        private SigmaProtocolInstance openingProofInstance;

        public BlindSignProtocolInstance(PSBlindSignProtocol protocol, String role, PSExtendedVerificationKey commonInput, SecretInput secretInput) {
            super(protocol, role);
            this.protocol = protocol;
            this.commonInput = commonInput;
            this.group = protocol.scheme.pp.getBilinearGroup();
            this.zn = group.getZn();

            this.receiverInput = role.equals("receiver") ? (ReceiverInput) secretInput : null;
            this.signerInput = role.equals("signer") ? (PSSigningKey) secretInput : null;
        }

        @Override
        protected void doRoundForFirstRole(int round) {
            switch (round) {
                case 0:
                    //Commit to desired messages
                    blindingFactor = zn.getUniformlyRandomElement();
                    commitment = commonInput.getGroup1ElementsYi().innerProduct(receiverInput.message).op(commonInput.getGroup1ElementG().pow(blindingFactor)); //g^{\sum y_i * m_i + blindingFactor}

                    //Send commitment
                    send("commitment", commitment.getRepresentation());

                    //Prove you can open commitment
                    openingProofInstance = new DamgardTechnique(new OpeningProof(), protocol.commitmentSchemeForDamgard)
                            .getProverInstance(new OpeningCommonInput(commitment), new OpeningSecretInput(receiverInput.message, blindingFactor));
                    runSubprotocolConcurrently("openingProof", openingProofInstance);
                    break;
                case 2:
                    //Wait for subprotocol to finish (internally, the sigma protocol's response is sent)
                    break;
                case 4:
                    //Receive blinded signature, unblind, finish
                    GroupElement sigma0 = group.getG1().getElement(receive("sigma0")); //h
                    GroupElement sigma1 = group.getG1().getElement(receive("blindedSigma1")).op(sigma0.pow(blindingFactor.neg())); //h^{x + \sum y_i * m_i}
                    resultSignature = new PSSignature(sigma0, sigma1);
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
                        GroupElement sigma0 = commonInput.getGroup1ElementG().pow(r);
                        send("sigma0", sigma0.getRepresentation()); //g^r
                        send("blindedSigma1", commitment.op(commonInput.getGroup1ElementG().pow(signerInput.getExponentX())).pow(r).getRepresentation()); //g^{r * (x + \sum y_i m_i)} * g^{r*blindingFactor}
                    } else {
                        throw new IllegalStateException("Proof was not accepted");
                    }
                    terminate();
                    break;
            }
        }

        public PSSignature getResultSignature() {
            return resultSignature;
        }

        public class OpeningProof extends DelegateProtocol {
            @Override
            protected SendThenDelegateFragment.SubprotocolSpec provideSubprotocolSpec(CommonInput commonInput, SendThenDelegateFragment.SubprotocolSpecBuilder builder) {
                ExponentExpressionVector msgVars = BlindSignProtocolInstance.this.commonInput.getGroup1ElementsYi().map((i, m) -> builder.addZnVariable("m"+i, zn), ExponentExpressionVector::new);
                ExponentExpr blindVar = builder.addZnVariable("blindingFactor", zn);
                GroupElementVector group1Yi = BlindSignProtocolInstance.this.commonInput.getGroup1ElementsYi();
                GroupElement g1 = BlindSignProtocolInstance.this.commonInput.getGroup1ElementG();

                builder.addSubprotocol("knowledgeOfOpening", new LinearStatementFragment(
                        group1Yi.expr().innerProduct(msgVars)
                                .op(g1.pow(blindVar)).isEqualTo(((OpeningCommonInput) commonInput).commitment)
                ));

                return builder.build();
            }

            @Override
            protected SendThenDelegateFragment.ProverSpec provideProverSpecWithNoSendFirst(CommonInput commonInput, SecretInput secretInput1, SendThenDelegateFragment.ProverSpecBuilder builder) {
                OpeningSecretInput secretInput = (OpeningSecretInput) secretInput1;
                secretInput.message.forEach((i, m) -> builder.putWitnessValue("m"+i, (Zn.ZnElement) m));
                builder.putWitnessValue("blindingFactor", secretInput.blindingFactor);

                return builder.build();
            }

            @Override
            public BigInteger getChallengeSpaceSize() {
                return BlindSignProtocolInstance.this.protocol.scheme.pp.getBilinearGroup().getG1().size();
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
