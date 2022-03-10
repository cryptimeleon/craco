package org.cryptimeleon.craco.sig.sps.agho11;

import org.cryptimeleon.math.random.RandomGenerator;
import org.cryptimeleon.math.structures.groups.debug.DebugBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.type3.bn.BarretoNaehrigBilinearGroup;


public class SPSAGHO11PublicParametersGen {
    /**
     * @param securityParameter The security parameter.
     * @param debugMode         Enable debug mode (Makes the PPs insecure!).
     * @param messageBlockLengths The k_M and k_N the instance is expected to sign
     * @return The public parameters for the AGHO11 SPS scheme
     */
    public static SPSAGHO11PublicParameters generatePublicParameters(int securityParameter, boolean debugMode, Integer[] messageBlockLengths) {
        BilinearGroup group;
        if (debugMode) {
            group = new DebugBilinearGroup(RandomGenerator.getRandomPrime(securityParameter), BilinearGroup.Type.TYPE_3);
        } else {
            group = new BarretoNaehrigBilinearGroup(securityParameter);
        }

        return new SPSAGHO11PublicParameters(group, messageBlockLengths);
    }
}
