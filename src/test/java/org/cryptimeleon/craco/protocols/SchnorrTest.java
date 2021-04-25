package org.cryptimeleon.craco.protocols;

import org.cryptimeleon.craco.protocols.arguments.sigma.ZnChallengeSpace;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.DelegateProtocol;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.LinearStatementFragment;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.SendThenDelegateFragment;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.setmembership.SetMembershipPublicParameters;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.setmembership.SmallerThanPowerFragment;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.setmembership.TwoSidedRangeProof;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.variables.SchnorrZnVariable;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zn;
import org.junit.jupiter.api.Test;


public class SchnorrTest extends ProtocolsTest {
    @Test
    public void testBasicSchnorr() {
        runTests(getSimpleSchnorrProof(), getSimpleSchnorrProofInput(), getSimpleSchnorrProofWitness());
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
            public ZnChallengeSpace getChallengeSpace(CommonInput commonInput) {
                return new ZnChallengeSpace(bilGroup.getZn());
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

                //m in [13, 60]
                builder.addSubprotocol("twoSidedRange", new TwoSidedRangeProof(mVar, 13, 23, setMembershipPublicParameters));

                //m smaller than 2^5
                builder.addSubprotocol("oneSidedRange", new SmallerThanPowerFragment(mVar, 2, 5, setMembershipPublicParameters));

                return builder.build();
            }
        };

        runTests(protocol);
    }
}
