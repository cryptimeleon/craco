package de.upb.crypto.craco.accumulators.nguyen;

import de.upb.crypto.craco.accumulators.interfaces.AccumulatorPublicParametersGen;
import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.factory.BilinearGroupFactory;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public class NguyenAccumulatorPublicParametersGen implements AccumulatorPublicParametersGen {

    /**
     * Calls to {@link #setup(int, int, boolean)} where <code>debugParameter</code> is <code>false</code>.
     *
     * @param securityParameter security parameter
     * @param size              upper bound for the number of accumulated {@link NguyenAccumulatorIdentity}
     * @return {@link NguyenAccumulatorPublicParameters} containing the universe of accumulatable
     * {@link NguyenAccumulatorIdentity}
     */
    @Override
    public NguyenAccumulatorPublicParameters setup(int securityParameter, int size) {
        return setup(securityParameter, size, false);
    }

    /**
     * This method generates {@link NguyenAccumulatorPublicParameters}. Therefore it generates a {@link BilinearGroup}
     * and calls {@link #setup(BilinearGroup, int)}.
     *
     * @param securityParameter security parameter  for group generation
     * @param size              upper bound for the number of accumulated {@link NguyenAccumulatorIdentity}
     * @param debugParameter    debug parameter for group generation
     * @return {@link NguyenAccumulatorPublicParameters} containing the universe of accumulatable
     * {@link NguyenAccumulatorIdentity}
     */
    public NguyenAccumulatorPublicParameters setup(int securityParameter, int size, boolean debugParameter) {
        BilinearGroup bilinearGroup = generateBilinearGroup(securityParameter, debugParameter);
        return setup(bilinearGroup, size);
    }

    /**
     * This method generates {@link NguyenAccumulatorPublicParameters} taking a {@link Group} and the number of
     * messages for the {@link NguyenAccumulatorPublicParameters}as input.
     *
     * @param bilinearGroup {@link BilinearGroup} used for {@link NguyenAccumulatorPublicParameters}
     * @param size        upper bound for the number of accumulated {@link NguyenAccumulatorIdentity}
     * @return {@link NguyenAccumulatorPublicParameters} containing the universe of accumulatable
     * {@link NguyenAccumulatorIdentity}
     */
    public NguyenAccumulatorPublicParameters setup(BilinearGroup bilinearGroup, int size) {
        Group G3 = bilinearGroup.getGT();
        BigInteger p = G3.size();

        // Generate public parameter
        GroupElement g = bilinearGroup.getG1().getUniformlyRandomNonNeutral().compute();
        GroupElement g_Tilde = bilinearGroup.getG2().getUniformlyRandomNonNeutral().compute();
        Zp zp = new Zp(p);
        Zp.ZpElement s = zp.getUniformlyRandomElement();
        GroupElement g_Tilde_Power_S = g_Tilde.pow(s).compute();

        GroupElement[] t = new GroupElement[size + 1];
        for (int i = 0; i < t.length; i++) {
            t[i] = g.pow(s.pow(BigInteger.valueOf(i))).compute();
        }
        List<NguyenAccumulatorIdentity> universe = Arrays.asList(new NguyenAccumulatorIdentity(zp
                .getUniformlyRandomElement()));

        return new NguyenAccumulatorPublicParameters(p, bilinearGroup, g, g_Tilde, g_Tilde_Power_S, t, universe);
    }


    /**
     * This is a utility method for generating a {@link BilinearGroup}.
     *
     * @param securityParameter security parameter
     * @param debugMode         debug parameter
     * @return {@link BilinearGroup}
     */
    private BilinearGroup generateBilinearGroup(int securityParameter, boolean debugMode) {
        // Get bilinear group from the factory
        BilinearGroupFactory facfac = new BilinearGroupFactory(securityParameter);
        facfac.setRequirements(BilinearGroup.Type.TYPE_3);
        facfac.setDebugMode(debugMode);
        return facfac.createBilinearGroup();
    }
}
