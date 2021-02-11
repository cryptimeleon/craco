package de.upb.crypto.craco.protocols.arguments.sigma.schnorr;

import de.upb.crypto.craco.protocols.CommonInput;
import de.upb.crypto.craco.protocols.SecretInput;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.variables.SchnorrVariableAssignment;
import de.upb.crypto.math.expressions.bool.BooleanExpression;
import de.upb.crypto.math.serialization.Representation;

/**
 * <p>A {@link de.upb.crypto.craco.protocols.arguments.sigma.SigmaProtocol} that sets up some (shared) variables and then runs subprotocols to prove something about these variables.</p>
 * <p>This is a a special case of a {@link SendThenDelegateProtocol} in which the {@link de.upb.crypto.craco.protocols.arguments.sigma.schnorr.SendThenDelegateFragment.SendFirstValue} is empty.</p>
 */
public abstract class DelegateProtocol extends SendThenDelegateProtocol {

    @Override
    protected SendThenDelegateFragment.ProverSpec provideProverSpec(CommonInput commonInput, SecretInput secretInput, SendThenDelegateFragment.ProverSpecBuilder builder) {
        builder.setSendFirstValue(SendThenDelegateFragment.SendFirstValue.EMPTY);
        return provideProverSpecWithNoSendFirst(commonInput, secretInput, builder);
    }

    /**
     * @see DelegateFragment#provideProverSpecWithNoSendFirst(SchnorrVariableAssignment, SendThenDelegateFragment.ProverSpecBuilder)
     */
    protected abstract SendThenDelegateFragment.ProverSpec provideProverSpecWithNoSendFirst(CommonInput commonInput, SecretInput secretInput, SendThenDelegateFragment.ProverSpecBuilder builder);

    @Override
    protected SendThenDelegateFragment.SendFirstValue recreateSendFirstValue(CommonInput commonInput, Representation repr) {
        return SendThenDelegateFragment.SendFirstValue.EMPTY;
    }

    @Override
    protected SendThenDelegateFragment.SendFirstValue simulateSendFirstValue(CommonInput commonInput) {
        return SendThenDelegateFragment.SendFirstValue.EMPTY;
    }

    @Override
    protected SendThenDelegateFragment.SubprotocolSpec provideSubprotocolSpec(CommonInput commonInput, SendThenDelegateFragment.SendFirstValue sendFirstValue, SendThenDelegateFragment.SubprotocolSpecBuilder builder) {
        return provideSubprotocolSpec(commonInput, builder);
    }

    /**
     * @see DelegateFragment#provideSubprotocolSpec(SendThenDelegateFragment.SubprotocolSpecBuilder)
     */
    protected abstract SendThenDelegateFragment.SubprotocolSpec provideSubprotocolSpec(CommonInput commonInput, SendThenDelegateFragment.SubprotocolSpecBuilder builder);

    @Override
    protected BooleanExpression provideAdditionalCheck(CommonInput commonInput, SendThenDelegateFragment.SendFirstValue sendFirstValue) {
        return BooleanExpression.TRUE;
    }
}
