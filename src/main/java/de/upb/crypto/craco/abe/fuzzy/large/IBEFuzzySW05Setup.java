package de.upb.crypto.craco.abe.fuzzy.large;

import de.upb.crypto.craco.common.WatersHash;
import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.factory.BilinearGroupFactory;
import de.upb.crypto.math.interfaces.hash.HashIntoStructure;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.math.BigInteger;

public class IBEFuzzySW05Setup {

    private IBEFuzzySW05PublicParameters pp;
    private IBEFuzzySW05MasterSecret msk;

    /**
     * Generates the master secret and the public parameters for a fuzzy
     * identity based encryption scheme. The parameter n specifies the number of
     * attributes in an {@link Identity}. The parameter universeThreshold
     * specifies the required number of attributes in the intersection to
     * successfully decrypt a {@link PlainText}. The parameter watersHash
     * selects between two possible hash functions: Waters Hash function or the
     * hash function from the group factory. The former yields a secure
     * construction in the standard model while the latter might be only secure
     * in the random oracle model. Typically, setting watersHash to false
     * provides much faster implementations.
     * <p>
     * To enable debugging modus, set debug to true. WARNING: This results in an
     * insecure instantiation of the underlying groups.
     *
     * @param securityParameter
     * @param n                 the maximum size of an identity
     * @param universeThreshold the required number of attributes in the intersection
     * @param watersHash        the hash function
     * @param debug             enable debugging
     */
    public void doKeyGen(int securityParameter, BigInteger n, BigInteger universeThreshold, boolean watersHash,
                         boolean debug) {
        // Public Parameter stuff
        BilinearGroupFactory fac = new BilinearGroupFactory(securityParameter);
        fac.setDebugMode(debug);
        fac.setRequirements(BilinearGroup.Type.TYPE_1, true, false, false);
        BilinearGroup group = fac.createBilinearGroup();

        doKeyGen(group, n, universeThreshold, watersHash);
    }

    /**
     * Setup with pre-made group
     *
     * @param group             group used for the scheme
     * @param n                 maximum size of an identity
     * @param universeThreshold required number of attributes in the intersection
     */
    public void doKeyGen(BilinearGroup group, BigInteger n, BigInteger universeThreshold, boolean watersHash) {
        // Public Parameter stuff
        pp = new IBEFuzzySW05PublicParameters();

        pp.setBilinearGroup(group);

        Zp zp = new Zp(pp.getGroupG1().size());

        ZpElement y = zp.getUniformlyRandomUnit();

        pp.setN(n);

        pp.setIdentityThresholdD(universeThreshold);
        // g in G_1
        pp.setG(pp.getGroupG1().getUniformlyRandomNonNeutral().compute());

        // g1 = g^y
        pp.setG1(pp.getG().pow(y).compute());

        // g2 in G1
        pp.setG2(pp.getGroupG1().getUniformlyRandomNonNeutral().compute());

        if (!watersHash) {
            pp.setHashToG1(group.getHashIntoG1());
        } else {
            HashIntoStructure hashToGroup = new WatersHash(pp.getGroupG1(), n.intValue() + 1);
            pp.setHashToG1(hashToGroup);
        }

        // msk =y
        msk = new IBEFuzzySW05MasterSecret(y);
    }

    public IBEFuzzySW05PublicParameters getPublicParameters() {
        return pp;
    }

    public IBEFuzzySW05MasterSecret getMasterSecret() {
        return msk;
    }
}