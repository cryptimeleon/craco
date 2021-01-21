package de.upb.crypto.craco.abe.kp.large;

import de.upb.crypto.craco.common.WatersHash;
import de.upb.crypto.math.interfaces.hash.HashIntoStructure;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.pairings.counting.CountingBilinearGroup;
import de.upb.crypto.math.pairings.generic.BilinearGroup;
import de.upb.crypto.math.pairings.type1.supersingular.SupersingularBilinearGroup;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class ABEKPGPSW06Setup {

    private ABEKPGPSW06PublicParameters pp;

    private ABEKPGPSW06MasterSecret msk;

    /**
     * Generate public parameters and the master secret.
     * <p>
     * Sets up public parameters and the master secret for a given security
     * parameter securityParameter. The parameter n specifies the maximum number
     * of attributes per cipher text. The parameter watersHash selects between
     * two possible hash functions: Waters Hash function or the hash function
     * from the group factory. The former yields a secure construction in the
     * standard model while the latter might be only secure in the random oracle
     * model. Typically, setting watersHash to false provides much faster
     * implementations.
     * <p>
     * To enable debugging modus, set debug to true. WARNING: This results in an
     * insecure instantiation of the underlying groups.
     *
     * @param securityParameter
     * @param n                 - maximum number of attributes per cipher text.
     * @param watersHash        - the hash function
     * @param debug             - enable debugging.
     */
    public void doKeyGen(int securityParameter, int n, boolean watersHash, boolean debug) {
        BilinearGroup group;
        if (debug) {
            group = new CountingBilinearGroup(securityParameter, BilinearGroup.Type.TYPE_1);
        } else {
            group = new SupersingularBilinearGroup(securityParameter);
        }

        doKeyGen(group, n, watersHash);
    }

    /**
     * Setup with pre-made group
     *
     * @param group      group used in the scheme
     * @param n
     * @param watersHash true: waters hash function; false: default hash function defined in the group
     */
    public void doKeyGen(BilinearGroup group, int n, boolean watersHash) {
        pp = new ABEKPGPSW06PublicParameters();
        pp.setBilinearGroup(group);
        pp.setN(BigInteger.valueOf(n));

        if (!watersHash) {
            pp.setHashToG1(group.getHashIntoG1());
        } else {
            pp.setHashToG1(new WatersHash(pp.getGroupG1(), n + 1));
        }

        Zp zp = new Zp(group.getG1().size());
        ZpElement y = zp.getUniformlyRandomUnit();

        // g_1 <- G_1 \setminus {1}
        pp.setG1Generator(pp.getGroupG1().getUniformlyRandomNonNeutral().compute());

        // Y = e(g,g)^y = e(g^y, g)
        pp.setY(pp.getBilinearMap().apply(pp.getG1Generator().pow(y).compute(), pp.getG1Generator()));

        msk = new ABEKPGPSW06MasterSecret(y);

        // T_i = g^t_i
        Map<BigInteger, GroupElement> T = new HashMap<>();

        for (int i = 0; i < n + 1; i++) {
            T.put(BigInteger.valueOf(i), pp.getG1Generator().pow(zp.getUniformlyRandomUnit()).compute());
        }
        pp.setT(T);
    }

    public ABEKPGPSW06PublicParameters getPublicParameters() {
        return pp;
    }

    public ABEKPGPSW06MasterSecret getMasterSecret() {
        return msk;
    }
}
