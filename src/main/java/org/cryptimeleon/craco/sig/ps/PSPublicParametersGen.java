package org.cryptimeleon.craco.sig.ps;

import org.cryptimeleon.math.random.RandomGenerator;
import org.cryptimeleon.math.structures.groups.debug.DebugBilinearGroup;;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.type3.bn.BarretoNaehrigBilinearGroup;

public class PSPublicParametersGen {
    /**
     * @param securityParameter The security parameter.
     * @param debugMode         Enable debug mode (Makes the PPs insecure!).
     * @return The public parameters for the Pointcheval Sanders signature scheme
     */
    public PSPublicParameters generatePublicParameter(int securityParameter, boolean debugMode) {
        BilinearGroup group;
        if (debugMode) {
            group = new DebugBilinearGroup(RandomGenerator.getRandomPrime(securityParameter), BilinearGroup.Type.TYPE_3);
        } else {
            group = new BarretoNaehrigBilinearGroup(securityParameter);
        }
        return new PSPublicParameters(group);
    }
}
