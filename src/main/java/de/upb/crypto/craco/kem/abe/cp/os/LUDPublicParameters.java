package de.upb.crypto.craco.kem.abe.cp.os;

import de.upb.crypto.craco.enc.asym.elgamal.ElgamalEncryption;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalPublicKey;
import de.upb.crypto.craco.common.interfaces.PublicParameters;
import de.upb.crypto.craco.kem.asym.elgamal.ElgamalKEM;
import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.util.RepresentationUtil;

import java.math.BigInteger;


/**
 * Container for public parameters of ElgmalLargeUniverseDelegationKEM.
 *
 * @author peter.guenther
 */
public class LUDPublicParameters implements PublicParameters {


    /**
     * The public key KEM that is used to construct the ABE KEM.
     */
    private ElgamalKEM baseKEM;

    /**
     * A set of pairing parameters used for implementing this KEM.
     */
    private BilinearGroup pairingParameters;

    /**
     * The Elgamal encryption key <e(g1,g2), e(g1,g2)^alpha that corresponds to
     * the MSK alpha.
     * This part is used for encapsulation of R in encaps.
     */
    private ElgamalPublicKey elgamalEncryptionKey;

    /**
     * group elements wrt. g1 and g2
     */
    public GroupElement g1, g2, u1, u2, h1, h2, v1, v2, w1, w2;
    //public HashIntoZn hashIntoExponent;

    public GroupElement getG1() {
        return g1;
    }

    public void setG1(GroupElement g1) {
        this.g1 = g1;
    }

    public GroupElement getG2() {
        return g2;
    }

    public void setG2(GroupElement g2) {
        this.g2 = g2;
    }

    public GroupElement getU1() {
        return u1;
    }

    public void setU1(GroupElement u1) {
        this.u1 = u1;
    }

    public GroupElement getU2() {
        return u2;
    }

    public void setU2(GroupElement u2) {
        this.u2 = u2;
    }

    public GroupElement getH1() {
        return h1;
    }

    public void setH1(GroupElement h1) {
        this.h1 = h1;
    }

    public GroupElement getH2() {
        return h2;
    }

    public void setH2(GroupElement h2) {
        this.h2 = h2;
    }

    public GroupElement getV1() {
        return v1;
    }

    public void setV1(GroupElement v1) {
        this.v1 = v1;
    }

    public GroupElement getV2() {
        return v2;
    }

    public void setV2(GroupElement v2) {
        this.v2 = v2;
    }

    public GroupElement getW1() {
        return w1;
    }

    public void setW1(GroupElement w1) {
        this.w1 = w1;
    }

    public GroupElement getW2() {
        return w2;
    }

    public void setW2(GroupElement w2) {
        this.w2 = w2;
    }


    private static String[] standaloneRepresentables = {"baseKEM", "pairingParameters"};
    private static String[] g1Elements = {"g1", "u1", "h1", "v1", "w1"};
    private static String[] g2Elements = {"g2", "u2", "h2", "v2", "w2"};


    @Override
    public Representation getRepresentation() {
        ObjectRepresentation toReturn = new ObjectRepresentation();
        for (String standaloneRepresentable : standaloneRepresentables) {
            RepresentationUtil.putStandaloneRepresentable(this, toReturn, standaloneRepresentable);
        }
        for (String elementRepresentable : g1Elements) {
            RepresentationUtil.putElement(this, toReturn, elementRepresentable);
        }
        for (String elementRepresentable : g2Elements) {
            RepresentationUtil.putElement(this, toReturn, elementRepresentable);
        }

        toReturn.put("elgamalEncryptionKey", elgamalEncryptionKey.getRepresentation());
        return toReturn;
    }

    public LUDPublicParameters(Representation r) {
        for (String standaloneRepresentable : standaloneRepresentables) {
            RepresentationUtil.restoreStandaloneRepresentable(this, r, standaloneRepresentable);
        }

        Group g1 = this.getPairingParameters().getG1();
        Group g2 = this.getPairingParameters().getG2();

        for (String elementRepresentable : g1Elements) {
            RepresentationUtil.restoreElement(this, r, elementRepresentable, g1);
        }
        for (String elementRepresentable : g2Elements) {
            RepresentationUtil.restoreElement(this, r, elementRepresentable, g2);
        }

        ElgamalEncryption elgamal = new ElgamalEncryption(pairingParameters.getGT());


        this.elgamalEncryptionKey = (ElgamalPublicKey) elgamal.getEncryptionKey(
                ((ObjectRepresentation) r).get("elgamalEncryptionKey"));

    }


    public LUDPublicParameters(ElgamalKEM base, BilinearGroup pp,// HashIntoZn hashIntoExponent,
                               ElgamalPublicKey egpk,
                               GroupElement g1,
                               GroupElement g2,
                               GroupElement u1,
                               GroupElement u2,
                               GroupElement h1,
                               GroupElement h2,
                               GroupElement v1,
                               GroupElement v2,
                               GroupElement w1,
                               GroupElement w2
    ) {
        baseKEM = base;
        this.elgamalEncryptionKey = egpk;
        this.pairingParameters = pp;
//		this.hashIntoExponent = hashIntoExponent;
        this.g1 = g1;
        this.g2 = g2;
        this.u1 = u1;
        this.u2 = u2;
        this.h1 = h1;
        this.h2 = h2;
        this.v1 = v1;
        this.v2 = v2;
        this.w1 = w1;
        this.w2 = w2;

    }

    public BigInteger getGroupSize() {
        return this.getPairingParameters().getG1().size();
    }

    public ElgamalKEM getBaseKEM() {
        return baseKEM;
    }

    public ElgamalPublicKey getElgamalEncryptionKey() {
        return elgamalEncryptionKey;
    }

    public BilinearGroup getPairingParameters() {
        return pairingParameters;
    }


    public void setBaseKEM(ElgamalKEM baseKEM) {
        this.baseKEM = baseKEM;
    }


    public void setPairingParameters(BilinearGroup pairingParameters) {
        this.pairingParameters = pairingParameters;
    }


    public void setElgamalEncryptionKey(ElgamalPublicKey elgamalEncryptionKey) {
        this.elgamalEncryptionKey = elgamalEncryptionKey;
    }

    public GroupElement getGtGenerator() {
        return this.elgamalEncryptionKey.getG();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((baseKEM == null) ? 0 : baseKEM.hashCode());
        result = prime * result + ((elgamalEncryptionKey == null) ? 0 : elgamalEncryptionKey.hashCode());
        result = prime * result + ((g1 == null) ? 0 : g1.hashCode());
        result = prime * result + ((g2 == null) ? 0 : g2.hashCode());
        result = prime * result + ((h1 == null) ? 0 : h1.hashCode());
        result = prime * result + ((h2 == null) ? 0 : h2.hashCode());
        result = prime * result + ((pairingParameters == null) ? 0 : pairingParameters.hashCode());
        result = prime * result + ((u1 == null) ? 0 : u1.hashCode());
        result = prime * result + ((u2 == null) ? 0 : u2.hashCode());
        result = prime * result + ((v1 == null) ? 0 : v1.hashCode());
        result = prime * result + ((v2 == null) ? 0 : v2.hashCode());
        result = prime * result + ((w1 == null) ? 0 : w1.hashCode());
        result = prime * result + ((w2 == null) ? 0 : w2.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (!(obj instanceof LUDPublicParameters))
            return false;
        LUDPublicParameters other = (LUDPublicParameters) obj;
        if (baseKEM == null) {
            if (other.baseKEM != null)
                return false;
        } else if (!baseKEM.equals(other.baseKEM))
            return false;
        if (elgamalEncryptionKey == null) {
            if (other.elgamalEncryptionKey != null)
                return false;
        } else if (!elgamalEncryptionKey.equals(other.elgamalEncryptionKey))
            return false;
        if (g1 == null) {
            if (other.g1 != null)
                return false;
        } else if (!g1.equals(other.g1))
            return false;
        if (g2 == null) {
            if (other.g2 != null)
                return false;
        } else if (!g2.equals(other.g2))
            return false;
        if (h1 == null) {
            if (other.h1 != null)
                return false;
        } else if (!h1.equals(other.h1))
            return false;
        if (h2 == null) {
            if (other.h2 != null)
                return false;
        } else if (!h2.equals(other.h2))
            return false;
        if (pairingParameters == null) {
            if (other.pairingParameters != null)
                return false;
        } else if (!pairingParameters.equals(other.pairingParameters))
            return false;
        if (u1 == null) {
            if (other.u1 != null)
                return false;
        } else if (!u1.equals(other.u1))
            return false;
        if (u2 == null) {
            if (other.u2 != null)
                return false;
        } else if (!u2.equals(other.u2))
            return false;
        if (v1 == null) {
            if (other.v1 != null)
                return false;
        } else if (!v1.equals(other.v1))
            return false;
        if (v2 == null) {
            if (other.v2 != null)
                return false;
        } else if (!v2.equals(other.v2))
            return false;
        if (w1 == null) {
            if (other.w1 != null)
                return false;
        } else if (!w1.equals(other.w1))
            return false;
        if (w2 == null) {
            if (other.w2 != null)
                return false;
        } else if (!w2.equals(other.w2))
            return false;
        return true;
    }


}
