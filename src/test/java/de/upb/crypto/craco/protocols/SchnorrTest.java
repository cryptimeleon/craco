package de.upb.crypto.craco.protocols;

import de.upb.crypto.craco.protocols.arguments.sigma.SigmaProtocol;
import de.upb.crypto.craco.protocols.arguments.sigma.instance.SigmaProtocolProverInstance;
import de.upb.crypto.craco.protocols.arguments.sigma.instance.SigmaProtocolVerifierInstance;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.DelegateProtocol;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.LinearStatementFragment;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.SendThenDelegateFragment;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.setmembership.SetMembershipPublicParameters;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.setmembership.SmallerThanPowerFragment;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.variables.SchnorrZnVariable;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.pairings.counting.CountingBilinearGroup;
import de.upb.crypto.math.pairings.counting.CountingGroup;
import de.upb.crypto.math.pairings.generic.BilinearGroup;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zn;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;


public class SchnorrTest {
    public static Group group = new CountingGroup("test", BigInteger.valueOf(13));
    public static BilinearGroup bilGroup = new CountingBilinearGroup(128, BilinearGroup.Type.TYPE_3,1);

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

        assert verifier.hasTerminated();
        assert verifier.isAccepting();
    }

    @Test
    public void testBasicSchnorr() {
        GroupElement g = group.getGenerator();
        Zn.ZnElement x = group.getUniformlyRandomExponent();
        GroupElement h = g.pow(x);

        runProtocol(new DelegateProtocol() {
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

        }, CommonInput.EMPTY, SecretInput.EMPTY);
    }

    @Test
    public void testCommittedRangeProof() {
        GroupElement g = bilGroup.getG1().getGenerator();
        GroupElement h = bilGroup.getG1().getUniformlyRandomNonNeutral();
        Zn.ZnElement m = bilGroup.getG1().getZn().valueOf(20);
        Zn.ZnElement r = bilGroup.getG1().getUniformlyRandomExponent();

        GroupElement C = g.pow(m).op(h.pow(r));

        SetMembershipPublicParameters setMembershipPublicParameters = SmallerThanPowerFragment.generatePublicParameters(bilGroup, 2);

        runProtocol(new DelegateProtocol() {
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
        }, CommonInput.EMPTY, SecretInput.EMPTY);
    }
}
