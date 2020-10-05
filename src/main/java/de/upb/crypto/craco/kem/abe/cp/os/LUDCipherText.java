package de.upb.crypto.craco.kem.abe.cp.os;

import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.common.interfaces.CipherText;
import de.upb.crypto.craco.common.interfaces.policy.Policy;
import de.upb.crypto.craco.kem.asym.elgamal.ElgamalKEMCiphertext;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.*;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.serialization.util.RepresentationUtil;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Map;

/**
 * Ciphertexts for encapsulation of symmetric keys with ElgamalLargeUniverseDelegationKEM.
 *
 * @author peter.guenther
 */
public class LUDCipherText implements CipherText {

    /**
     * The policy of this ciphertext.
     */
    @Represented
    public Policy policy;

    /**
     * R e(g1,g2)^alpha s  in Gt
     * where H(R) is used to blind symmetric key, alpha is MSK and s is ElGamal nonce for encryption.
     */
    @Represented(restorer = "GT")
    public GroupElement c;

    /**
     * g2^s in G2
     */
    @Represented(restorer = "G2")
    public GroupElement c0;

    /**
     * k xor H(R) where k is symmetric key
     */
    @Represented
    public ByteArrayImplementation encaps;

    /**
     * ABE komponents for reconstruction of s in exponent.
     * *
     * C_i,1=w2^lambda_i v2^ti
     * <p>
     * <p>
     * C_i,2=(u2^H(\rho(i)) h2)^-ti
     * <p>
     * <p>
     * <p>
     * C_i,3=g2^ti
     */
    @Represented(restorer = "int -> [G2]")
    public Map<BigInteger, GroupElement[]> abeComponents;

    public LUDCipherText() {

    }

    public LUDCipherText(Policy policy,
                         ElgamalKEMCiphertext elgamalct,
                         GroupElement c0,
                         Map<BigInteger, GroupElement[]> abeKomponents) {
        this.c0 = c0;
        this.policy = policy;
        this.encaps = elgamalct.getSymmetricEncryption();
        this.c = elgamalct.getElgamalCipherText().getC2();
        this.abeComponents = abeKomponents;
    }

    public LUDCipherText(Representation repr, Group groupG2, Group groupGT) {
        new ReprUtil(this).register(groupG2, "G2").register(groupGT, "GT").deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public Policy getPolicy() {
        return policy;
    }

    public void setPolicy(Policy policy) {
        this.policy = policy;
    }

    public GroupElement getC() {
        return c;
    }

    public void setC(GroupElement c) {
        this.c = c;
    }

    public GroupElement getC0() {
        return c0;
    }

    public void setC0(GroupElement c0) {
        this.c0 = c0;
    }

    public ByteArrayImplementation getEncaps() {
        return encaps;
    }

    @Override
    public String toString() {
        String result = "";
        result += "Policy: " + policy + " ";
        result += "c: " + c + " ";
        result += "c0: " + c0 + " ";
        result += "encaps: " + encaps;
        for (Map.Entry<BigInteger, GroupElement[]> entry : abeComponents.entrySet()) {
            BigInteger i = entry.getKey();
            result += "C_1," + i + ": " + entry.getValue()[0];
            result += "C_2," + i + ": " + entry.getValue()[1];
            result += "C_3," + i + ": " + entry.getValue()[2];
        }
        return result;

    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((abeComponents == null) ? 0 : abeComponents.hashCode());
        result = prime * result + ((c == null) ? 0 : c.hashCode());
        result = prime * result + ((c0 == null) ? 0 : c0.hashCode());
        result = prime * result + ((encaps == null) ? 0 : encaps.hashCode());
        result = prime * result + ((policy == null) ? 0 : policy.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (!(obj instanceof LUDCipherText))
            return false;
        LUDCipherText other = (LUDCipherText) obj;
        if (abeComponents == null) {
            if (other.abeComponents != null)
                return false;
        } else {
            /*
             * Non-genric test for Map on arrays.
             *
             */
            if (abeComponents.size() != other.abeComponents.size()) {
                return false;
            }
            for (Map.Entry<BigInteger, GroupElement[]> entry : abeComponents.entrySet()) {
                if (!other.abeComponents.containsKey(entry.getKey()))
                    return false;
                if (!Arrays.equals(entry.getValue(), other.abeComponents.get(entry.getKey())))
                    return false;
            }
        }

        if (c == null) {
            if (other.c != null)
                return false;
        } else if (!c.equals(other.c))
            return false;
        if (c0 == null) {
            if (other.c0 != null)
                return false;
        } else if (!c0.equals(other.c0))
            return false;
        if (encaps == null) {
            if (other.encaps != null)
                return false;
        } else if (!encaps.equals(other.encaps))
            return false;
        if (policy == null) {
            if (other.policy != null)
                return false;
        } else if (!policy.equals(other.policy))
            return false;
        return true;
    }

    public void setEncaps(ByteArrayImplementation encaps) {
        this.encaps = encaps;
    }

    public Map<BigInteger, GroupElement[]> getAbeComponents() {
        return abeComponents;
    }

    public void setAbeComponents(Map<BigInteger, GroupElement[]> abeKomponents) {
        this.abeComponents = abeKomponents;
    }


}
