package org.cryptimeleon.craco.sig.sps;

import org.cryptimeleon.math.random.RandomGenerator;
import org.cryptimeleon.math.structures.groups.debug.DebugBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.type3.bn.BarretoNaehrigBilinearGroup;

import java.util.function.BiFunction;

/**
 * generates a set of generic public parameters to be used by SPS schemes.
 *
 */
public class SPSPublicParametersGen {

    public static SPSPublicParameters generateParameters(int securityParameter,
                                                         boolean debugMode) {
        BilinearGroup group;
        if (debugMode) {
            group = new DebugBilinearGroup(RandomGenerator.getRandomPrime(securityParameter), BilinearGroup.Type.TYPE_3);
        } else {
            group = new BarretoNaehrigBilinearGroup(securityParameter);
        }

        return new SPSPublicParameters(group);
    }

    /**
     * generates a set of public parameters based on a pre-made {@link BilinearGroup}.
     * This works for any subclass of SPSPublicParameters that provides a constructor that takes
     * just a {@link BilinearGroup} as its parameter
     */
    public static <PPType extends SPSPublicParameters> PPType generateParameters(
            BiFunction<BilinearGroup,Integer,PPType> constructor, BilinearGroup bGroup, int messageLength) {
        return constructor.apply(bGroup, messageLength);
    }

}
