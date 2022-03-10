package org.cryptimeleon.craco.sig.sps.akot15;

import org.cryptimeleon.math.random.RandomGenerator;
import org.cryptimeleon.math.structures.groups.debug.DebugBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.type3.bn.BarretoNaehrigBilinearGroup;

/**
 * generates a set of public parameters to be used by the schemes:
 * {@link org.cryptimeleon.craco.sig.sps.akot15.pos.SPSPOSSignatureScheme},
 * {@link org.cryptimeleon.craco.sig.sps.akot15.tc.TCAKOT15CommitmentScheme},
 * {@link org.cryptimeleon.craco.sig.sps.akot15.tcgamma.TCGAKOT15CommitmentScheme}
 *
 */
public class AKOT15SharedPublicParametersGen {

    public static AKOT15SharedPublicParameters generateParameters(int securityParameter, int numberOfMessages, boolean debugMode) {
        BilinearGroup group;
        if (debugMode) {
            group = new DebugBilinearGroup(RandomGenerator.getRandomPrime(securityParameter), BilinearGroup.Type.TYPE_3);
        } else {
            group = new BarretoNaehrigBilinearGroup(securityParameter);
        }

        return new AKOT15SharedPublicParameters(group, numberOfMessages);
    }

}
