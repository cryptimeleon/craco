package de.upb.crypto.craco.protocols.arguments.sigma.schnorr.setmembership;

import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.DelegateFragment;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.LinearExponentStatementFragment;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.variables.SchnorrVariableAssignment;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.variables.SchnorrZnVariable;
import de.upb.crypto.math.expressions.exponent.ExponentEmptyExpr;
import de.upb.crypto.math.expressions.exponent.ExponentExpr;
import de.upb.crypto.math.pairings.generic.BilinearGroup;
import de.upb.crypto.math.structures.integers.IntegerRing;
import de.upb.crypto.math.structures.zn.Zn;

import java.math.BigInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * A fragment to prove a statement of the form "0 ≤ member < base^power"
 */
public class SmallerThanPowerFragment extends DelegateFragment {
    protected final int base;
    protected final int power;
    protected final ExponentExpr member;
    protected final SetMembershipPublicParameters pp;

    /**
     * Instantiates the fragment.
     * @param member an expression whose value shall be between 0 and base^power. In the easiest case, this is a {@link SchnorrZnVariable}, but it can be any linear combination of {@link SchnorrZnVariable}s.
     * @param base a number (generally the bigger this number, the bigger the public parameters but the shorter the proof)
     * @param power a number (protocol computation and communication cost is linear in this number)
     * @param pp honestly generated public parameters for a set membership proof for {0, ..., base-1}. Can be generated {@link SmallerThanPowerFragment#generatePublicParameters(BilinearGroup, int)}
     */
    public SmallerThanPowerFragment(ExponentExpr member, int base, int power, SetMembershipPublicParameters pp) {
        this.base = base;
        this.power = power;
        this.member = member;
        this.pp = pp;

        if (pp.signatures.size() != base || IntStream.range(0, base).anyMatch(i -> !pp.signatures.containsKey(BigInteger.valueOf(i))))
            throw new IllegalArgumentException("Unfit SetMembershiptPublicParameters");
    }

    /**
     * Generates public parameters to use for a given base.
     * @param group the group to use for this fragment
     * @param base the desired base (see constructor).
     */
    public static SetMembershipPublicParameters generatePublicParameters(BilinearGroup group, int base) {
        return SetMembershipPublicParameters.generate(group, IntStream.range(0, base).mapToObj(BigInteger::valueOf).collect(Collectors.toSet()));
    }

    @Override
    protected ProverSpec provideProverSpecWithNoSendFirst(SchnorrVariableAssignment externalWitnesses, ProverSpecBuilder builder) {
        Zn.ZnElement memberVal = this.member.evaluate(pp.getZn(), externalWitnesses);

        //Decompose memberVal into digits
        BigInteger[] digits = IntegerRing.decomposeIntoDigits(memberVal.getInteger(), BigInteger.valueOf(base), power);

        //Add digits to witnesses
        for (int i=0; i<power; i++)
            builder.putWitnessValue("digit"+i, pp.getZn().valueOf(digits[i]));

        return builder.build();
    }

    @Override
    protected SubprotocolSpec provideSubprotocolSpec(SubprotocolSpecBuilder builder) {
        //Need to prove knowledge of digits
        SchnorrZnVariable[] digits = new SchnorrZnVariable[power];
        for (int i=0; i<power; i++)
            digits[i] = builder.addZnVariable("digit"+i, pp.getZn());

        //... such that those digits represent member
        Zn.ZnElement base = pp.getZn().valueOf(this.base);
        ExponentExpr weightedSum = new ExponentEmptyExpr();
        for (int i=0; i<power; i++)
            weightedSum = weightedSum.add(digits[i].mul(base.pow(i)));
        builder.addSubprotocol("digitSum", new LinearExponentStatementFragment(weightedSum.isEqualTo(member), pp.getZn()));

        //... and each digit is in the set {0,...,base-1} of valid digits
        for (int i=0; i<power; i++)
            builder.addSubprotocol("digit"+i+"valid", new SetMembershipFragment(pp, digits[i]));

        return builder.build();
    }
}
