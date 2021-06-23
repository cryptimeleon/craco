package org.cryptimeleon.craco.protocols;

import org.cryptimeleon.craco.protocols.arguments.sigma.ChallengeSpace;
import org.cryptimeleon.craco.protocols.arguments.sigma.SigmaProtocol;
import org.cryptimeleon.craco.protocols.arguments.sigma.ZnChallengeSpace;
import org.cryptimeleon.craco.protocols.arguments.sigma.partial.AndProof;
import org.cryptimeleon.craco.protocols.arguments.sigma.partial.OrProof;
import org.cryptimeleon.craco.protocols.arguments.sigma.partial.ProofOfPartialKnowledge;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.SendFirstValue;
import org.cryptimeleon.math.expressions.bool.BooleanExpression;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zn;
import org.junit.jupiter.api.Test;

public class PartialKnowledgeTest extends ProtocolsTest {
    @Test
    public void testSimpleOr() {
        Zn.ZnElement x1 = g.getStructure().getUniformlyRandomExponent();
        GroupElement h1 = g.pow(x1);
        SigmaProtocol orProof = new OrProof(getSimpleSchnorrProof(), getSimpleSchnorrProof(h1));

        runTests(orProof, new CommonInput.CommonInputVector(getSimpleSchnorrProofInput(), getSimpleSchnorrProofInput()), new OrProof.OrProofSecretInput(getSimpleSchnorrProofWitness(), false));
        runTests(orProof, new CommonInput.CommonInputVector(getSimpleSchnorrProofInput(), getSimpleSchnorrProofInput()), new OrProof.OrProofSecretInput(getSimpleSchnorrProofWitness(x1), true));
    }

    @Test
    public void testSimpleAnd() {
        Zn.ZnElement x1 = g.getStructure().getUniformlyRandomExponent();
        GroupElement h1 = g.pow(x1);
        SigmaProtocol andProof = new AndProof(getSimpleSchnorrProof(), getSimpleSchnorrProof(h1));

        runTests(andProof, new CommonInput.CommonInputVector(getSimpleSchnorrProofInput(), getSimpleSchnorrProofInput()), new SecretInput.SecretInputVector(getSimpleSchnorrProofWitness(), getSimpleSchnorrProofWitness(x1)));
    }

    @Test
    public void testProofOfPartialKnowledge() {
        Zn.ZnElement x1 = g.getStructure().getUniformlyRandomExponent();
        GroupElement h1 = g.pow(x1);
        GroupElement sendFirst = h1.pow(x1);

        SigmaProtocol protocol = new ProofOfPartialKnowledge() {
            @Override
            protected ProtocolTree provideProtocolTree(CommonInput commonInput, SendFirstValue sendFirstValue) {
                return or(
                        and(leaf("simple", getSimpleSchnorrProof(), getSimpleSchnorrProofInput()), leaf("h1", getSimpleSchnorrProof(h1), getSimpleSchnorrProofInput())),
                        leaf("sendFirstDlog", getSimpleSchnorrProof(((SendFirstValue.AlgebraicSendFirstValue) sendFirstValue).getGroupElement(0)), getSimpleSchnorrProofInput())
                );
            }

            @Override
            protected ProverSpec provideProverSpec(CommonInput commonInput, SecretInput secretInput, ProverSpecBuilder builder) {
                builder.setSendFirstValue(new SendFirstValue.AlgebraicSendFirstValue(sendFirst));
                //builder.putSecretInput("simple", getSimpleSchnorrProofWitness());
                //builder.putSecretInput("h1", getSimpleSchnorrProofWitness(x1));
                builder.putSecretInput("sendFirstDlog", getSimpleSchnorrProofWitness(x1.square()));
                return builder.build();
            }

            @Override
            protected SendFirstValue restoreSendFirstValue(CommonInput commonInput, Representation repr) {
                return new SendFirstValue.AlgebraicSendFirstValue(repr, g.getStructure());
            }

            @Override
            protected SendFirstValue simulateSendFirstValue(CommonInput commonInput) {
                return new SendFirstValue.AlgebraicSendFirstValue(g.getStructure().getUniformlyRandomElement());
            }

            @Override
            protected BooleanExpression provideAdditionalCheck(CommonInput commonInput, SendFirstValue sendFirstValue) {
                return BooleanExpression.TRUE;
            }

            @Override
            public ChallengeSpace getChallengeSpace(CommonInput commonInput) {
                return new ZnChallengeSpace(g.getStructure().getZn());
            }
        };

        runTests(protocol, CommonInput.EMPTY, SecretInput.EMPTY);
    }
}
