package org.cryptimeleon.craco.sig.bbs;

import org.cryptimeleon.math.structures.groups.counting.CountingBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.type1.supersingular.SupersingularBilinearGroup;

/**
 * Does the key generation for the BBS-B signature scheme respectively organization in the anonymous credential system
 *
 *
 */
public class BBSBKeyGen {
    private BBSBPublicParameter pp;
    private BilinearGroup group;

    public BBSBPublicParameter doKeyGen(int securityParameter) {
        return doKeyGen(securityParameter, false);
    }

    /**
     * Generates public parameters for BBSB
     *
     * @param securityParameter the number of bits of security
     * @param debugMode         if set to true, uses insecure but fast groups.
     * @return the generated public parameters
     */
    public BBSBPublicParameter doKeyGen(int securityParameter, boolean debugMode) {
        if (debugMode) {
            group = new CountingBilinearGroup(securityParameter, BilinearGroup.Type.TYPE_1);
        } else {
            group = new SupersingularBilinearGroup(securityParameter);
        }

        return doKeyGen(group);
    }

    public BBSBPublicParameter doKeyGen(BilinearGroup group) {
        pp = new BBSBPublicParameter(group, group.getHashIntoZGroupExponent());
        pp.setG2(pp.getGroupG1().getUniformlyRandomElement());
        pp.setG1(pp.getGroupHom().apply(pp.getG2()));

        return pp;
    }

    public BilinearGroup getGroup() {
        return group;
    }
}
