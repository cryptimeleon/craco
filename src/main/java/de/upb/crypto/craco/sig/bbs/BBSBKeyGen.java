package de.upb.crypto.craco.sig.bbs;

import de.upb.crypto.math.pairings.counting.CountingBilinearGroup;
import de.upb.crypto.math.pairings.generic.BilinearGroup;
import de.upb.crypto.math.pairings.type1.supersingular.SupersingularBilinearGroup;
import de.upb.crypto.math.structures.zn.HashIntoZn;

/**
 * Does the key generation for the BBS-B signature scheme respectively organization in the anonymous credential system
 *
 * @author Fabian Eidens
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
     * @param securityParameter
     * @param debugMode         if set to true, uses insecure but fast groups.
     * @return
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
        pp = new BBSBPublicParameter(group, (HashIntoZn) group.getHashIntoZGroupExponent());
        pp.setG2(pp.getGroupG1().getUniformlyRandomElement());
        pp.setG1(pp.getGroupHom().apply(pp.getG2()));

        return pp;
    }

    public BilinearGroup getGroup() {
        return group;
    }
}
