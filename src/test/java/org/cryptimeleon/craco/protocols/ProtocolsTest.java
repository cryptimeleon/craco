package org.cryptimeleon.craco.protocols;

import org.cryptimeleon.craco.protocols.arguments.damgardtechnique.DamgardTechnique;
import org.cryptimeleon.craco.protocols.arguments.fiatshamir.FiatShamirProof;
import org.cryptimeleon.craco.protocols.arguments.fiatshamir.FiatShamirProofSystem;
import org.cryptimeleon.craco.protocols.arguments.sigma.SigmaProtocol;
import org.cryptimeleon.craco.protocols.arguments.sigma.ZnChallengeSpace;
import org.cryptimeleon.craco.protocols.arguments.sigma.instance.SigmaProtocolProverInstance;
import org.cryptimeleon.craco.protocols.arguments.sigma.instance.SigmaProtocolVerifierInstance;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.DelegateProtocol;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.LinearStatementFragment;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.SendThenDelegateFragment;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.variables.SchnorrZnVariable;
import org.cryptimeleon.math.random.RandomGenerator;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.debug.DebugBilinearGroup;
import org.cryptimeleon.math.structures.groups.debug.DebugGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class ProtocolsTest {
    public static Group group = new DebugGroup("test", RandomGenerator.getRandomPrime(80));
    public static BilinearGroup bilGroup = new DebugBilinearGroup(BilinearGroup.Type.TYPE_3);
    protected static final GroupElement g = group.getGenerator();
    protected static final Zn.ZnElement x = group.getUniformlyRandomExponent();
    protected static final GroupElement h = g.pow(x);


    public void runTests(SigmaProtocol protocol) {
        runTests(protocol, CommonInput.EMPTY, SecretInput.EMPTY);
    }

    public void runTests(SigmaProtocol protocol, CommonInput commonInput, SecretInput secretInput) {
        runProtocol(protocol, commonInput, secretInput);
        runProtocol(new DamgardTechnique(protocol, DamgardTechnique.generateCommitmentScheme(group)), commonInput, secretInput);
        runNoninteractiveProof(new FiatShamirProofSystem(protocol), commonInput, secretInput);
    }

    private void runProtocol(SigmaProtocol protocol, CommonInput commonInput, SecretInput secretInput) {
        SigmaProtocolProverInstance prover = protocol.getProverInstance(commonInput, secretInput);
        SigmaProtocolVerifierInstance verifier = protocol.getVerifierInstance(commonInput);

        Representation announcement = prover.nextMessage(null);
        System.out.println(announcement);
        Representation challenge = verifier.nextMessage(announcement);
        System.out.println(challenge);
        Representation response = prover.nextMessage(challenge);
        System.out.println(response);
        verifier.nextMessage(response);

        assertTrue(verifier.hasTerminated());
        assertTrue(verifier.isAccepting());
    }

    private void runNoninteractiveProof(FiatShamirProofSystem proofSystem, CommonInput commonInput, SecretInput secretInput) {
        FiatShamirProof proof = proofSystem.createProof(commonInput, secretInput);
        assertTrue(proofSystem.checkProof(commonInput, proof));

        byte[] additionalData = "foo".getBytes(StandardCharsets.UTF_8);
        proof = proofSystem.createProof(commonInput, secretInput, additionalData);
        assertTrue(proofSystem.checkProof(commonInput, proof, additionalData));
        assertFalse(proofSystem.checkProof(commonInput, proof, new byte[] {123}));
    }

    public static SigmaProtocol getSimpleSchnorrProof() {
        return getSimpleSchnorrProof(h);
    }

    public static SigmaProtocol getSimpleSchnorrProof(GroupElement h) {
        return new SimpleSchnorrProof(g,h);
    }

    public static CommonInput getSimpleSchnorrProofInput() {
        return CommonInput.EMPTY;
    }

    public static SecretInput getSimpleSchnorrProofWitness() {
        return getSimpleSchnorrProofWitness(x);
    }

    public static SecretInput getSimpleSchnorrProofWitness(Zn.ZnElement x) {
        return new SimpleSchnorrProof.SchnorrWitness(x);
    }

    protected static class SimpleSchnorrProof extends DelegateProtocol {
        private final GroupElement g, h;

        public SimpleSchnorrProof(GroupElement g, GroupElement h) {
            this.g = g;
            this.h = h;
        }

        @Override
        protected SendThenDelegateFragment.ProverSpec provideProverSpecWithNoSendFirst(CommonInput commonInput, SecretInput secretInput, SendThenDelegateFragment.ProverSpecBuilder builder) {
            builder.putWitnessValue("x", ((SchnorrWitness) secretInput).x);
            return builder.build();
        }

        @Override
        protected SendThenDelegateFragment.SubprotocolSpec provideSubprotocolSpec(CommonInput commonInput, SendThenDelegateFragment.SubprotocolSpecBuilder builder) {
            SchnorrZnVariable dlog = builder.addZnVariable("x", group.getZn());
            builder.addSubprotocol("schnorr", new LinearStatementFragment(g.pow(dlog).isEqualTo(h)));
            return builder.build();
        }

        @Override
        public ZnChallengeSpace getChallengeSpace(CommonInput commonInput) {
            return new ZnChallengeSpace(group.size());
        }

        public static class SchnorrWitness implements SecretInput {
            public final Zn.ZnElement x;

            public SchnorrWitness(Zn.ZnElement x) {
                this.x = x;
            }
        }
    }
}
