package org.cryptimeleon.craco.protocols.arguments.sigma.schnorr;

import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.craco.protocols.arguments.sigma.SigmaProtocol;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.variables.SchnorrVariableAssignment;
import org.cryptimeleon.math.expressions.bool.BooleanExpression;
import org.cryptimeleon.math.serialization.Representation;

/**
 * <p>A {@link SigmaProtocol} that sets up some (shared) variables and then runs subprotocols to prove something about these variables.</p>
 * <p>This is a a special case of a {@link SendThenDelegateProtocol} in which the {@link SendFirstValue} is empty.</p>
 */
public abstract class DelegateProtocol extends SendThenDelegateProtocol {

    @Override
    protected SendThenDelegateFragment.ProverSpec provideProverSpec(CommonInput commonInput, SecretInput secretInput, SendThenDelegateFragment.ProverSpecBuilder builder) {
        builder.setSendFirstValue(SendFirstValue.EMPTY);
        return provideProverSpecWithNoSendFirst(commonInput, secretInput, builder);
    }

    /**
     * @see DelegateFragment#provideProverSpecWithNoSendFirst(SchnorrVariableAssignment, SendThenDelegateFragment.ProverSpecBuilder)
     */
    protected abstract SendThenDelegateFragment.ProverSpec provideProverSpecWithNoSendFirst(CommonInput commonInput, SecretInput secretInput, SendThenDelegateFragment.ProverSpecBuilder builder);

    @Override
    protected SendFirstValue restoreSendFirstValue(CommonInput commonInput, Representation repr) {
        return SendFirstValue.EMPTY;
    }

    @Override
    protected SendFirstValue simulateSendFirstValue(CommonInput commonInput) {
        return SendFirstValue.EMPTY;
    }

    @Override
    protected SendThenDelegateFragment.SubprotocolSpec provideSubprotocolSpec(CommonInput commonInput, SendFirstValue sendFirstValue, SendThenDelegateFragment.SubprotocolSpecBuilder builder) {
        return provideSubprotocolSpec(commonInput, builder);
    }

    /**
     * @see DelegateFragment#provideSubprotocolSpec(SendThenDelegateFragment.SubprotocolSpecBuilder)
     */
    protected abstract SendThenDelegateFragment.SubprotocolSpec provideSubprotocolSpec(CommonInput commonInput, SendThenDelegateFragment.SubprotocolSpecBuilder builder);

    @Override
    protected BooleanExpression provideAdditionalCheck(CommonInput commonInput, SendFirstValue sendFirstValue) {
        return BooleanExpression.TRUE;
    }
}
