package de.upb.crypto.craco.protocols;

import de.upb.crypto.craco.protocols.arguments.damgardtechnique.DamgardTechnique;
import de.upb.crypto.craco.protocols.arguments.fiatshamir.FiatShamirProof;
import de.upb.crypto.craco.protocols.arguments.fiatshamir.FiatShamirProofSystem;
import de.upb.crypto.craco.protocols.arguments.sigma.SigmaProtocol;
import de.upb.crypto.craco.protocols.arguments.sigma.instance.SigmaProtocolProverInstance;
import de.upb.crypto.craco.protocols.arguments.sigma.instance.SigmaProtocolVerifierInstance;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.DelegateProtocol;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.LinearStatementFragment;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.SendThenDelegateFragment;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.setmembership.SetMembershipPublicParameters;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.setmembership.SmallerThanPowerFragment;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.variables.SchnorrZnVariable;
import de.upb.crypto.math.random.RandomGenerator;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.structures.groups.counting.CountingGroup;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.groups.Group;
import de.upb.crypto.math.structures.groups.counting.CountingBilinearGroup;
import de.upb.crypto.math.structures.groups.elliptic.BilinearGroup;

import de.upb.crypto.math.structures.rings.zn.Zn;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;


public class SchnorrTest {
    public static Group group = new CountingGroup("test", RandomGenerator.getRandomPrime(80));
    public static BilinearGroup bilGroup = new CountingBilinearGroup(128, BilinearGroup.Type.TYPE_3,1);

    protected void runProtocol(SigmaProtocol protocol) {
        runProtocol(protocol, CommonInput.EMPTY, SecretInput.EMPTY);
    }

    protected void runProtocol(SigmaProtocol protocol, CommonInput commonInput, SecretInput secretInput) {
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

    protected void runNoninteractiveProof(FiatShamirProofSystem proofSystem) {
        runNoninteractiveProof(proofSystem, CommonInput.EMPTY, SecretInput.EMPTY);
    }

    protected void runNoninteractiveProof(FiatShamirProofSystem proofSystem, CommonInput commonInput, SecretInput secretInput) {
        FiatShamirProof proof = proofSystem.createProof(commonInput, secretInput);
        assertTrue(proofSystem.checkProof(commonInput, proof));

        byte[] additionalData = "foo".getBytes(StandardCharsets.UTF_8);
        proof = proofSystem.createProof(commonInput, secretInput, additionalData);
        assertTrue(proofSystem.checkProof(commonInput, proof, additionalData));
        assertFalse(proofSystem.checkProof(commonInput, proof, new byte[] {123}));
    }

    @Test
    public void testBasicSchnorr() {
        GroupElement g = group.getGenerator();
        Zn.ZnElement x = group.getUniformlyRandomExponent();
        GroupElement h = g.pow(x);

        DelegateProtocol protocol = new DelegateProtocol() {
            @Override
            protected SendThenDelegateFragment.ProverSpec provideProverSpecWithNoSendFirst(CommonInput commonInput, SecretInput secretInput, SendThenDelegateFragment.ProverSpecBuilder builder) {
                builder.putWitnessValue("x", x);
                return builder.build();
            }

            @Override
            protected SendThenDelegateFragment.SubprotocolSpec provideSubprotocolSpec(CommonInput commonInput, SendThenDelegateFragment.SubprotocolSpecBuilder builder) {
                SchnorrZnVariable dlog = builder.addZnVariable("x", group.getZn());
                builder.addSubprotocol("schnorr", new LinearStatementFragment(g.pow(dlog).isEqualTo(h)));
                return builder.build();
            }

            @Override
            public BigInteger getChallengeSpaceSize() {
                return group.size();
            }

        };

        runProtocol(protocol);
        runProtocol(new DamgardTechnique(protocol, DamgardTechnique.generateCommitmentScheme(group)));
        runNoninteractiveProof(new FiatShamirProofSystem(protocol));
    }

    @Test
    public void testCommittedRangeProof() {
        GroupElement g = bilGroup.getG1().getGenerator();
        GroupElement h = bilGroup.getG1().getUniformlyRandomNonNeutral();
        Zn.ZnElement m = bilGroup.getG1().getZn().valueOf(20);
        Zn.ZnElement r = bilGroup.getG1().getUniformlyRandomExponent();

        GroupElement C = g.pow(m).op(h.pow(r));

        SetMembershipPublicParameters setMembershipPublicParameters = SmallerThanPowerFragment.generatePublicParameters(bilGroup, 2);

        DelegateProtocol protocol = new DelegateProtocol() {
            @Override
            public BigInteger getChallengeSpaceSize() {
                return bilGroup.getG1().size();
            }

            @Override
            protected SendThenDelegateFragment.ProverSpec provideProverSpecWithNoSendFirst(CommonInput commonInput, SecretInput secretInput, SendThenDelegateFragment.ProverSpecBuilder builder) {
                builder.putWitnessValue("m", m);
                builder.putWitnessValue("r", r);
                return builder.build();
            }

            @Override
            protected SendThenDelegateFragment.SubprotocolSpec provideSubprotocolSpec(CommonInput commonInput, SendThenDelegateFragment.SubprotocolSpecBuilder builder) {
                SchnorrZnVariable mVar = builder.addZnVariable("m", bilGroup.getG1().getZn());
                SchnorrZnVariable rVar = builder.addZnVariable("r", bilGroup.getG1().getZn());

                //Can open commitment
                builder.addSubprotocol("commitment open", new LinearStatementFragment(g.pow(mVar).op(h.pow(rVar)).isEqualTo(C)));

                //m is smaller than 2^5
                builder.addSubprotocol("range", new SmallerThanPowerFragment(mVar, 2, 5, setMembershipPublicParameters));

                return builder.build();
            }
        };

        runProtocol(protocol);
        runProtocol(new DamgardTechnique(protocol, DamgardTechnique.generateCommitmentScheme(group)));
        runNoninteractiveProof(new FiatShamirProofSystem(protocol));
    }
}
