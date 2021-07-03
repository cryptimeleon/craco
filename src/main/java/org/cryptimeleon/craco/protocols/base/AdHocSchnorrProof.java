package org.cryptimeleon.craco.protocols.base;

import org.cryptimeleon.craco.commitment.CommitmentScheme;
import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.craco.protocols.arguments.damgardtechnique.DamgardTechnique;
import org.cryptimeleon.craco.protocols.arguments.fiatshamir.FiatShamirProofSystem;
import org.cryptimeleon.craco.protocols.arguments.sigma.ZnChallengeSpace;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.*;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.setmembership.SetMembershipPublicParameters;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.setmembership.SmallerThanPowerFragment;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.variables.SchnorrGroupElemVariable;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.variables.SchnorrZnVariable;
import org.cryptimeleon.math.expressions.Substitution;
import org.cryptimeleon.math.expressions.VariableExpression;
import org.cryptimeleon.math.expressions.bool.ExponentEqualityExpr;
import org.cryptimeleon.math.expressions.bool.GroupEqualityExpr;
import org.cryptimeleon.math.expressions.exponent.BasicNamedExponentVariableExpr;
import org.cryptimeleon.math.expressions.exponent.ExponentExpr;
import org.cryptimeleon.math.expressions.group.BasicNamedGroupVariableExpr;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * A Schnorr proof designed to easily work with {@link BaseProtocol}.
 *
 * <p>
 * Statements are specified using simple {@link BasicNamedExponentVariableExpr}s.
 * Use {@link #builder(Zn)} to construct and {@link #witnessOf} to specify where to source your witness (can be any Java object, in which case variable "x" is sourced from object member {@code object.x}. This can be your {@link BaseProtocolInstance} that stores all the variables relevant to the protocol).
 * The {@link CommonInput} for this is just {@code null}.
 * </p>
 *
 */
public class AdHocSchnorrProof extends DelegateProtocol {
    protected final Zn zn;
    protected Map<String, FragmentCreator> fragmentCreators;
    private HashSet<BasicNamedExponentVariableExpr> exponentVars;
    private HashMap<BasicNamedGroupVariableExpr, Group> groupElemVars;

    protected AdHocSchnorrProof(Zn zn, Map<String, FragmentCreator> fragmentCreators) {
        this.zn = zn;
        this.fragmentCreators = fragmentCreators;
        init();
    }

    private void init() {
        //Collect variables
        exponentVars = new HashSet<>();
        groupElemVars = new HashMap<>();

        fragmentCreators.forEach((name, creator) -> creator.forEachVariable(v -> {
            if (v instanceof BasicNamedExponentVariableExpr)
                exponentVars.add((BasicNamedExponentVariableExpr) v);
            if (v instanceof BasicNamedGroupVariableExpr)
                groupElemVars.put((BasicNamedGroupVariableExpr) v, creator.getGroupOfVariable(v));
        }));
    }

    @Override
    protected SendThenDelegateFragment.ProverSpec provideProverSpecWithNoSendFirst(CommonInput commonInput, SecretInput secretInput, SendThenDelegateFragment.ProverSpecBuilder builder) {
        Function<String, ?> witnessSource = ((BaseSchnorrProofInput) secretInput).witnessSource;
        for (BasicNamedExponentVariableExpr var : exponentVars) {
            Object witness = witnessSource.apply(var.getName());
            if (witness instanceof BigInteger)
                witness = zn.valueOf((BigInteger) witness);
            builder.putWitnessValue(var.getName(), (Zn.ZnElement) witness);
        }

        for (BasicNamedGroupVariableExpr var : groupElemVars.keySet()) {
            Object witness = witnessSource.apply(var.getName());
            builder.putWitnessValue(var.getName(), (GroupElement) witness);
        }

        return builder.build();
    }

    @Override
    protected SendThenDelegateFragment.SubprotocolSpec provideSubprotocolSpec(CommonInput commonInput, SendThenDelegateFragment.SubprotocolSpecBuilder builder) {
        HashMap<VariableExpression, SchnorrZnVariable> znVars = new HashMap<>();
        HashMap<VariableExpression, SchnorrGroupElemVariable> groupVars = new HashMap<>();
        for (BasicNamedExponentVariableExpr var : exponentVars)
            znVars.put(var, builder.addZnVariable(var.getName(), zn));
        groupElemVars.forEach((v, group) -> {
            groupVars.put(v, builder.addGroupElemVariable(v.getName(), group));
        });

        Substitution substitution = Substitution.join(znVars::get, groupVars::get);
        fragmentCreators.forEach((name, creator) -> {
            try {
                builder.addSubprotocol(name, creator.createFragment(substitution));
            } catch (RuntimeException e) {
                throw new RuntimeException("Error instantiating fragment "+name, e);
            }
        });

        return builder.build();
    }

    @Override
    public ZnChallengeSpace getChallengeSpace(CommonInput commonInput) {
        return new ZnChallengeSpace(zn);
    }

    /**
     * Get the witnesses from a Java object's object variables.
     */
    public static BaseSchnorrProofInput witnessOf(Object witnessSource) {
        return new BaseSchnorrProofInput(name -> {
            try {
                Field field = witnessSource.getClass().getDeclaredField(name);
                field.setAccessible(true);
                return field.get(witnessSource);
            } catch (NoSuchFieldException | IllegalAccessException e) {
                throw new IllegalArgumentException(e);
            }
        });
    }

    /**
     * Get the witnesses by applying the given function.
     */
    public static BaseSchnorrProofInput witnessOf(Function<String, ?> witnessSource) {
        return new BaseSchnorrProofInput(witnessSource);
    }

    public static class BaseSchnorrProofInput implements SecretInput {
        public final Function<String, ?> witnessSource;

        public BaseSchnorrProofInput(Function<String, ?> witnessSource) {
            this.witnessSource = witnessSource;
        }
    }

    public static BaseSchnorrProofBuilder builder(Zn zn) {
        return new BaseSchnorrProofBuilder(zn);
    }

    public static class BaseSchnorrProofBuilder {
        public final Zn zn;
        protected Map<String, FragmentCreator> fragmentCreators = new HashMap<>();

        public BaseSchnorrProofBuilder(Zn zn) {
            this.zn = zn;
        }

        public BaseSchnorrProofBuilder addLinearStatement(String name, GroupEqualityExpr statement) {
            fragmentCreators.put(name, new LinearFragmentCreator(statement));
            return this;
        }

        public BaseSchnorrProofBuilder addLinearExponentStatement(String name, ExponentEqualityExpr statement) {
            fragmentCreators.put(name, new LinearExponentFragmentCreator(statement, zn));
            return this;
        }

        public BaseSchnorrProofBuilder addSmallerThanPowerStatement(String name, ExponentExpr smallValue, int base, int power, SetMembershipPublicParameters setMembershipPp) {
            fragmentCreators.put(name, new SmallerThanPowerFragmentCreator(smallValue, base, power, setMembershipPp));
            return this;
        }

        public AdHocSchnorrProof build() {
            return new AdHocSchnorrProof(zn, fragmentCreators);
        }

        public FiatShamirProofSystem buildFiatShamir() {
            return new FiatShamirProofSystem(build());
        }

        public DamgardTechnique buildInteractiveDamgard(CommitmentScheme commitmentSchemeForDamgard) {
            return new DamgardTechnique(build(), commitmentSchemeForDamgard);
        }
    }

    private interface FragmentCreator {
        SchnorrFragment createFragment(Substitution substitution);
        void forEachVariable(Consumer<VariableExpression> action);
        default Group getGroupOfVariable(VariableExpression var) {
            throw new IllegalArgumentException("Cannot infer group type for var");
        }
    }

    private static class LinearFragmentCreator implements FragmentCreator {
        public final GroupEqualityExpr expr;

        public LinearFragmentCreator(GroupEqualityExpr expr) {
            this.expr = expr;
        }

        @Override
        public SchnorrFragment createFragment(Substitution substitution) {
            return new LinearStatementFragment(expr.substitute(substitution));
        }

        @Override
        public void forEachVariable(Consumer<VariableExpression> action) {
            expr.getVariables().forEach(action);
        }

        @Override
        public Group getGroupOfVariable(VariableExpression var) {
            return expr.getGroup();
        }
    }

    private static class LinearExponentFragmentCreator implements FragmentCreator {
        public final ExponentEqualityExpr expr;
        public final Zn zn;

        public LinearExponentFragmentCreator(ExponentEqualityExpr expr, Zn zn) {
            this.expr = expr;
            this.zn = zn;
        }

        @Override
        public SchnorrFragment createFragment(Substitution substitution) {
            return new LinearExponentStatementFragment(expr.substitute(substitution), zn);
        }

        @Override
        public void forEachVariable(Consumer<VariableExpression> action) {
            expr.getVariables().forEach(action);
        }
    }

    private static class SmallerThanPowerFragmentCreator implements FragmentCreator {
        public final ExponentExpr expr;
        public final int base, power;
        public final SetMembershipPublicParameters setMembershipPp;

        public SmallerThanPowerFragmentCreator(ExponentExpr expr, int base, int power, SetMembershipPublicParameters setMembershipPp) {
            this.expr = expr;
            this.base = base;
            this.power = power;
            this.setMembershipPp = setMembershipPp;
        }

        @Override
        public SchnorrFragment createFragment(Substitution substitution) {
            return new SmallerThanPowerFragment(expr.substitute(substitution), base, power, setMembershipPp);
        }

        @Override
        public void forEachVariable(Consumer<VariableExpression> action) {
            expr.getVariables().forEach(action);
        }
    }
}
