package org.cryptimeleon.craco.sig.sps.akot15.pos;

import org.cryptimeleon.craco.sig.sps.agho11.SPSAGHO11PublicParameters;
import org.cryptimeleon.math.random.RandomGenerator;
import org.cryptimeleon.math.structures.groups.debug.DebugBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.type3.bn.BarretoNaehrigBilinearGroup;

public class SPSPOSPublicParametersGen {

    public static SPSPOSPublicParameters generateParameters(int securityParameter, int numberOfMessages, boolean debugMode) {
        BilinearGroup group;
        if (debugMode) {
            group = new DebugBilinearGroup(RandomGenerator.getRandomPrime(securityParameter), BilinearGroup.Type.TYPE_3);
        } else {
            group = new BarretoNaehrigBilinearGroup(securityParameter);
        }

        return new SPSPOSPublicParameters(group, numberOfMessages);
    }

}
