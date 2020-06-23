package de.upb.crypto.craco.abe.ibe;

import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.factory.BilinearGroupFactory;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.math.BigInteger;

public class FullIdentSetup {

    private FullIdentPublicParameters pp;

    private FullIdentMasterSecret msk;

    /**
     * Generates the master secret and the public parameters for a FullIdent
     * based encryption scheme.
     *
     * @param securityParameter the security parameter
     * @param block_size        the size of a plaintext in bytes
     * @param debug             enable debugging
     */
    public void doKeyGen(int securityParameter, BigInteger block_size, boolean debug) {
        // Generate bilinear group
        BilinearGroupFactory fac = new BilinearGroupFactory(securityParameter);
        fac.setDebugMode(debug);
        fac.setRequirements(BilinearGroup.Type.TYPE_1);
        BilinearGroup group = fac.createBilinearGroup();

        doKeyGen(group, block_size);
    }

    /**
     * Setup with pre-made group
     *
     * @param group      group used in the scheme
     * @param block_size size of plaintext in bytes
     */
    public void doKeyGen(BilinearGroup group, BigInteger block_size) {
        pp = new FullIdentPublicParameters();
        pp.setN(block_size);

        pp.setHashToG1(group.getHashIntoG1());

        pp.setGroupG1(group.getG1());
        pp.setGroupG2(group.getGT());

        pp.setE(group.getBilinearMap());
        Zp zp = new Zp(pp.getGroupG1().size());

        // Do the scheme setup stuff
        // s <- Zp*
        ZpElement s = zp.getUniformlyRandomUnit();
        // P is a generator in G1
        pp.setP(pp.getGroupG1().getUniformlyRandomNonNeutral());
        // P_pub = P^s
        pp.setP_pub(pp.getP().pow(s));
        msk = new FullIdentMasterSecret(s);
    }

    public FullIdentPublicParameters getPublicParameters() {
        return pp;
    }

    public FullIdentMasterSecret getMasterSecret() {
        return msk;
    }
}
