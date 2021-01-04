package de.upb.crypto.craco.sig.ps;

import de.upb.crypto.math.pairings.counting.CountingBilinearGroup;
import de.upb.crypto.math.pairings.generic.BilinearGroup;
import de.upb.crypto.math.pairings.type3.bn.BarretoNaehrigBilinearGroup;

public class PSPublicParametersGen {
    /**
     * @param securityParameter The security parameter.
     * @param debugMode         Enable debug mode (Makes the PPs insecure!).
     * @return The public parameters for the Pointcheval Sanders signature scheme
     */
    public PSPublicParameters generatePublicParameter(int securityParameter, boolean debugMode) {
        BilinearGroup group;
        if (debugMode) {
            group = new CountingBilinearGroup(securityParameter, BilinearGroup.Type.TYPE_3);
        } else {
            group = new BarretoNaehrigBilinearGroup(securityParameter);
        }
        return new PSPublicParameters(group);
    }
}
