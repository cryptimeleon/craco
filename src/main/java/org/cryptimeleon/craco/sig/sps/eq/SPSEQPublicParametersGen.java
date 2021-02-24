package org.cryptimeleon.craco.sig.sps.eq;

import org.cryptimeleon.math.structures.groups.counting.CountingBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.type3.bn.BarretoNaehrigBilinearGroup;

public class SPSEQPublicParametersGen {
    /**
     * @param securityParameter The security parameter.
     * @param debugMode         Enable debug mode (Makes the PPs insecure!).
     * @return The public parameters for the Pointcheval Sanders signature scheme
     */
    public SPSEQPublicParameters generatePublicParameter(int securityParameter, boolean debugMode) {
        BilinearGroup group;
        if (debugMode) {
            group = new CountingBilinearGroup(securityParameter, BilinearGroup.Type.TYPE_3);
        } else {
            group = new BarretoNaehrigBilinearGroup(securityParameter);
        }

        return new SPSEQPublicParameters(group);
    }
}
