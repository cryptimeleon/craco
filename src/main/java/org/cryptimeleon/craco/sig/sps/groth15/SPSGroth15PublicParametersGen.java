package org.cryptimeleon.craco.sig.sps.groth15;

import org.cryptimeleon.math.random.RandomGenerator;
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
    public SPSGroth15PublicParameters generatePublicParameter(int securityParameter, Groth15Type type,int numberOfMessages , boolean debugMode) {
        BilinearGroup group;
        if (debugMode) {
            group = new DebugBilinearGroup(RandomGenerator.getRandomPrime(securityParameter), BilinearGroup.Type.TYPE_3);
        } else {
            group = new BarretoNaehrigBilinearGroup(securityParameter);
        }

        return generatePublicParameter(group, type, numberOfMessages);
    }

    public SPSGroth15PublicParameters generatePublicParameter(BilinearGroup bilinearGroup, Groth15Type type, int numberOfMessages) {
        return new SPSGroth15PublicParameters(bilinearGroup, type, numberOfMessages);
    }


    public enum Groth15Type{
        type1, type2;
    }
}
