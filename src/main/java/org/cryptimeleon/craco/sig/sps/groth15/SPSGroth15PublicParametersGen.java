package org.cryptimeleon.craco.sig.sps.groth15;

import org.cryptimeleon.math.structures.groups.debug.DebugBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.type3.bn.BarretoNaehrigBilinearGroup;

;

public class SPSGroth15PublicParametersGen {
    /**
     * @param securityParameter The security parameter.
     * @param debugMode         Enable debug mode (Makes the PPs insecure!).
     * @return The public parameters
     */
    public SPSGroth15PublicParameters generatePublicParameter(int securityParameter, Groth15Type type, boolean debugMode) {
        BilinearGroup group;
        if (debugMode) {
            group = new DebugBilinearGroup(securityParameter, BilinearGroup.Type.TYPE_3);
        } else {
            group = new BarretoNaehrigBilinearGroup(securityParameter);
        }

        return new SPSGroth15PublicParameters(group, type);

    }

    public enum Groth15Type{
        type1, type2;
    }
}
