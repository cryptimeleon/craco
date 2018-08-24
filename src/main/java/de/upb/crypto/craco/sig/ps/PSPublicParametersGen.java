package de.upb.crypto.craco.sig.ps;

import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.factory.BilinearGroupFactory;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;

public class PSPublicParametersGen {
    /**
     * @param securityParameter The security parameter.
     * @param debugMode         Enable debug mode (Makes the PPs insecure!).
     * @return The public parameters for the Pointcheval Sanders signature scheme
     */
    public PSPublicParameters generatePublicParameter(int securityParameter, boolean debugMode) {
        BilinearMap bilinearMap; // G1 x G2 -> GT

        // Get bilinear group from the factory
        BilinearGroupFactory fac = new BilinearGroupFactory(securityParameter);
        fac.setDebugMode(debugMode);
        fac.setRequirements(BilinearGroup.Type.TYPE_3);
        BilinearGroup group = fac.createBilinearGroup();

        bilinearMap = group.getBilinearMap();

        return new PSPublicParameters(bilinearMap);
    }
}
