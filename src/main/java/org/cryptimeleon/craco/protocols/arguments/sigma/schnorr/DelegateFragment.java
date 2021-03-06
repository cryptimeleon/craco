package org.cryptimeleon.craco.protocols.arguments.sigma.schnorr;

import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.setmembership.SmallerThanPowerFragment;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.variables.SchnorrVariableAssignment;
import org.cryptimeleon.math.expressions.bool.BooleanExpression;
import org.cryptimeleon.math.serialization.Representation;

/**
 * <p>A {@link SchnorrFragment} that sets up some (shared) variables and then runs subprotocols to prove something about these variables.</p>
 * <p>This is a a special case of a {@link SendThenDelegateFragment} in which the {@link SendFirstValue} is empty.</p>
 */
public abstract class DelegateFragment extends SendThenDelegateFragment {
    @Override
    protected ProverSpec provideProverSpec(SchnorrVariableAssignment externalWitnesses, ProverSpecBuilder builder) {
        builder.setSendFirstValue(SendFirstValue.EMPTY);
        return provideProverSpecWithNoSendFirst(externalWitnesses, builder);
    }

    /**
     * <p>
     * Run by the prover to set up witness values for variables this fragment proves knowledge of itself (i.e. those specified in {@link DelegateFragment#provideSubprotocolSpec(SubprotocolSpecBuilder)}).
     * </p>
     * <p>
     * A typical example implementation can be found in {@link SmallerThanPowerFragment}.
     * </p>
     *
     * @param externalWitnesses the witness values for external variables
     * @param builder helper object to instantiate a {@link ProverSpec}
     * @return the specification of witness values for this fragment's own variables. Returned by {@link ProverSpecBuilder#build()}.
     */
    protected abstract ProverSpec provideProverSpecWithNoSendFirst(SchnorrVariableAssignment externalWitnesses, ProverSpecBuilder builder);

    @Override
    protected SendFirstValue restoreSendFirstValue(Representation repr) {
        return SendFirstValue.EMPTY;
    }

    @Override
    protected SendFirstValue simulateSendFirstValue() {
        return SendFirstValue.EMPTY;
    }

    @Override
    protected SubprotocolSpec provideSubprotocolSpec(SendFirstValue sendFirstValue, SubprotocolSpecBuilder builder) {
        return provideSubprotocolSpec(builder);
    }

    protected abstract SubprotocolSpec provideSubprotocolSpec(SubprotocolSpecBuilder builder);

    @Override
    protected BooleanExpression provideAdditionalCheck(SendFirstValue sendFirstValue) {
        return BooleanExpression.TRUE;
    }
}
