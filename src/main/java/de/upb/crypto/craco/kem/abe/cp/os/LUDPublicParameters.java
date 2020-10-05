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
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.serialization.util.RepresentationUtil;

import java.math.BigInteger;
import java.util.Objects;


/**
 * Container for public parameters of ElgmalLargeUniverseDelegationKEM.
 *
 * @author peter.guenther
 */
public class LUDPublicParameters implements PublicParameters {


    /**
     * The public key KEM that is used to construct the ABE KEM.
     */
    @Represented
    private ElgamalKEM baseKEM;

    /**
     * A set of pairing parameters used for implementing this KEM.
     */
    @Represented
    private BilinearGroup pairingParameters;

    /**
     * The Elgamal encryption key <e(g1,g2), e(g1,g2)^alpha that corresponds to
     * the MSK alpha.
     * This part is used for encapsulation of R in encaps.
     */
    @Represented(restorer = "baseKEM::getEncryptionScheme")
    private ElgamalPublicKey elgamalEncryptionKey;

    /**
     * group elements wrt. g1 and g2
     */
    @Represented(restorer = "pairingParameters::getG1")
    public GroupElement g1, u1, h1, v1, w1;
    @Represented(restorer = "pairingParameters::getG2")
    public GroupElement g2, u2, h2, v2, w2;

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


    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public LUDPublicParameters(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    public LUDPublicParameters(ElgamalKEM base, BilinearGroup pp, ElgamalPublicKey egpk,
                               GroupElement g1, GroupElement g2, GroupElement u1, GroupElement u2,
                               GroupElement h1, GroupElement h2, GroupElement v1, GroupElement v2,
                               GroupElement w1, GroupElement w2) {
        baseKEM = base;
        this.elgamalEncryptionKey = egpk;
        this.pairingParameters = pp;
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
        if (getClass() != obj.getClass())
            return false;
        LUDPublicParameters other = (LUDPublicParameters) obj;
        return Objects.equals(baseKEM, other.baseKEM)
                && Objects.equals(elgamalEncryptionKey, other.elgamalEncryptionKey)
                && Objects.equals(g1, other.g1)
                && Objects.equals(g2, other.g2)
                && Objects.equals(h1, other.h1)
                && Objects.equals(h2, other.h2)
                && Objects.equals(pairingParameters, other.pairingParameters)
                && Objects.equals(u1, other.u1)
                && Objects.equals(u2, other.u2)
                && Objects.equals(v1, other.v1)
                && Objects.equals(v2, other.v2)
                && Objects.equals(w1, other.w1)
                && Objects.equals(w2, other.w2);
    }


}
