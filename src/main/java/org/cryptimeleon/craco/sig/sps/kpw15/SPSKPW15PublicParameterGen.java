package org.cryptimeleon.craco.sig.sps.kpw15;

import org.cryptimeleon.math.random.RandomGenerator;
import org.cryptimeleon.math.structures.groups.debug.DebugBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.type3.bn.BarretoNaehrigBilinearGroup;

public class SPSKPW15PublicParameterGen {

    /**
     * @param securityParameter The security parameter.
     * @param debugMode         Enable debug mode (Makes the PPs insecure!).
     * @param messageLength The message length the instance is expected to sign
     * @return The public parameters for the AGHO11 SPS scheme
     */
    public SPSKPW15PublicParameters generatePublicParameter(int securityParameter, boolean debugMode, int messageLength) {
        BilinearGroup group;
        if (debugMode) {
            group = new DebugBilinearGroup(RandomGenerator.getRandomPrime(securityParameter), BilinearGroup.Type.TYPE_3);
        } else {
            group = new BarretoNaehrigBilinearGroup(securityParameter);
        }

        return new SPSKPW15PublicParameters(group, messageLength);
    }
}
