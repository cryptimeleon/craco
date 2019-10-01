package de.upb.crypto.craco.sig.ps18;

import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.factory.BilinearGroupFactory;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;

/**
 * Class for generating public parameters for the Pointcheval Sanders 2018 (Section 4.2)
 * signature scheme.
 *
 * @author Raphael Heitjohann
 */
public class PS18PublicParametersGen {

    /**
     * @param securityParameter The security parameter.
     * @param debugMode         Enable debug mode (Makes the PPs insecure!).
     * @return The public parameters for the Pointcheval Sanders 2018 signature scheme.
     */
    public PS18PublicParameters generatePublicParameter(int securityParameter, boolean debugMode) {
        // TODO: This is exactly the same as for [PS16]. Would be nicer to reuse that one.
        BilinearMap bilinearMap;

        BilinearGroupFactory fac = new BilinearGroupFactory(securityParameter);
        fac.setDebugMode(debugMode);
        fac.setRequirements(BilinearGroup.Type.TYPE_3);
        BilinearGroup group = fac.createBilinearGroup();

        bilinearMap = group.getBilinearMap();

        return new PS18PublicParameters(bilinearMap);
    }

}
