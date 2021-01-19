package de.upb.crypto.craco.kem.abe.cp.os;

import de.upb.crypto.craco.enc.asym.elgamal.ElgamalPublicKey;
import de.upb.crypto.craco.kem.asym.elgamal.ElgamalKEM;
import de.upb.crypto.math.interfaces.hash.HashFunction;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.pairings.generic.BilinearGroup;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Factory for ElgamalLargeUniverseDelegationKEM.
 *
 *
 */
public class LUDSetup {

    private LUDMasterSecret msk;
    private ElgamalLargeUniverseDelegationKEM scheme;

    public LUDSetup() { }

    public void setup(BilinearGroup pp, HashFunction md) {
        BigInteger p = pp.getG1().size();

        if (!p.equals(pp.getG2().size())) {
            throw new IllegalArgumentException("Size of G1 and G2 do not match.");
        }

        if (!p.equals(pp.getG2().size())) {
            throw new IllegalArgumentException("Size of G1 and Gt do not match.");
        }

        Zp zp = new Zp(p);
        ElgamalKEM elgamalKEM = new ElgamalKEM(pp.getGT(), md);


        GroupElement g1 = pp.getG1().getGenerator();
        GroupElement g2 = pp.getG2().getGenerator();
        GroupElement gt = pp.getBilinearMap().apply(g1, g2).compute();

        ZpElement a = zp.getUniformlyRandomElement();
        ZpElement b = zp.getUniformlyRandomElement();
        ZpElement c = zp.getUniformlyRandomElement();
        ZpElement d = zp.getUniformlyRandomElement();
        ZpElement alpha = zp.getUniformlyRandomElement();

        GroupElement u1 = g1.pow(a).compute();
        GroupElement u2 = g2.pow(a).compute();

        GroupElement h1 = g1.pow(b).compute();
        GroupElement h2 = g2.pow(b).compute();

        GroupElement v1 = g1.pow(c).compute();
        GroupElement v2 = g2.pow(c).compute();

        GroupElement w1 = g1.pow(d).compute();
        GroupElement w2 = g2.pow(d).compute();


        GroupElement ht = gt.pow(alpha).compute();

        ElgamalPublicKey egpk = new ElgamalPublicKey(pp.getGT(), gt, ht);

        LUDPublicParameters pub = new LUDPublicParameters(elgamalKEM, pp, egpk,
                g1, g2, u1, u2, h1, h2, v1, v2, w1, w2);

        scheme = new ElgamalLargeUniverseDelegationKEM(pub);
        msk = new LUDMasterSecret(alpha);

    }

    public LUDPublicParameters getPublicParameters() {
        return scheme.getPublicParameters();
    }

    public LUDMasterSecret getMasterSecretKey() {
        return msk;
    }

    public ElgamalLargeUniverseDelegationKEM getScheme() {
        return scheme;
    }
    
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((msk == null) ? 0 : msk.hashCode());
        result = prime * result + ((scheme == null) ? 0 : scheme.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        LUDSetup other = (LUDSetup) obj;
        return Objects.equals(msk, other.msk)
                && Objects.equals(scheme, other.scheme);
    }
}
