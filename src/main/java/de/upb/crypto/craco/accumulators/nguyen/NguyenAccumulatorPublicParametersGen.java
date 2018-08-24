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
     * This method generates {@link NguyenAccumulatorPublicParameters}. Therefore it generates a {@link BilinearMap}
     * and calls {@link #setup(BilinearMap, int)}.
     *
     * @param securityParameter security parameter  for group generation
     * @param size              upper bound for the number of accumulated {@link NguyenAccumulatorIdentity}
     * @param debugParameter    debug parameter for group generation
     * @return {@link NguyenAccumulatorPublicParameters} containing the universe of accumulatable
     * {@link NguyenAccumulatorIdentity}
     */
    public NguyenAccumulatorPublicParameters setup(int securityParameter, int size, boolean debugParameter) {
        BilinearMap bilinearMap = generateBilinearMap(securityParameter, debugParameter);
        return setup(bilinearMap, size);
    }

    /**
     * This method generates {@link NguyenAccumulatorPublicParameters} taking a {@link Group} and the number of
     * messages for the {@link NguyenAccumulatorPublicParameters}as input.
     *
     * @param bilinearMap {@link BilinearMap} used for {@link NguyenAccumulatorPublicParameters}
     * @param size        upper bound for the number of accumulated {@link NguyenAccumulatorIdentity}
     * @return {@link NguyenAccumulatorPublicParameters} containing the universe of accumulatable
     * {@link NguyenAccumulatorIdentity}
     */
    public NguyenAccumulatorPublicParameters setup(BilinearMap bilinearMap, int size) {
        Group G3 = bilinearMap.getGT();
        BigInteger p = G3.size();

        // Generate public parameter
        GroupElement g = bilinearMap.getG1().getUniformlyRandomNonNeutral();
        GroupElement g_Tilde = bilinearMap.getG2().getUniformlyRandomNonNeutral();
        Zp zp = new Zp(p);
        Zp.ZpElement s = zp.getUniformlyRandomElement();
        GroupElement g_Tilde_Power_S = g_Tilde.pow(s);

        GroupElement[] t = new GroupElement[size + 1];
        for (int i = 0; i < t.length; i++) {
            t[i] = g.pow(s.pow(BigInteger.valueOf(i)));
        }
        List<NguyenAccumulatorIdentity> universe = Arrays.asList(new NguyenAccumulatorIdentity(zp
                .getUniformlyRandomElement()));

        return new NguyenAccumulatorPublicParameters(p, bilinearMap, g, g_Tilde, g_Tilde_Power_S, t, universe);
    }


    /**
     * This is a utility method for generating a {@link BilinearMap}.
     *
     * @param securityParameter security parameter
     * @param debugMode         debug parameter
     * @return {@link BilinearMap}
     */
    private BilinearMap generateBilinearMap(int securityParameter, boolean debugMode) {
        BilinearMap bilinearMap; // G1 x G2 -> GT

        // Get bilinear group from the factory
        BilinearGroupFactory facfac = new BilinearGroupFactory(securityParameter);
        facfac.setRequirements(BilinearGroup.Type.TYPE_3);
        facfac.setDebugMode(debugMode);
        BilinearGroup fac = facfac.createBilinearGroup();

        bilinearMap = fac.getBilinearMap();
        return bilinearMap;
    }
}
