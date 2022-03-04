package org.cryptimeleon.craco.sig.sps.akot15.xsig;

import org.cryptimeleon.math.random.RandomGenerator;
import org.cryptimeleon.math.structures.groups.debug.DebugBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.type3.bn.BarretoNaehrigBilinearGroup;


/**
 * generates a set of public parameters to be used by the {@link SPSXSIGSignatureScheme}.
 *
 */
public class SPSXSIGPublicParametersGen {

    public static SPSXSIGPublicParameters generatePublicParameters(int securityParameter,
                                                            int numberOfMessageBlocks,
                                                            boolean debugMode) {
        BilinearGroup group;
        if(debugMode){
            group = new DebugBilinearGroup(
                    RandomGenerator.getRandomPrime(securityParameter),
                    BilinearGroup.Type.TYPE_3
            );
        }
        else{
            group = new BarretoNaehrigBilinearGroup(securityParameter);
        }

        return new SPSXSIGPublicParameters(group, numberOfMessageBlocks);
    }

}
