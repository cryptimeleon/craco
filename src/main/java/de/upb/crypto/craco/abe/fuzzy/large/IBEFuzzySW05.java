package de.upb.crypto.craco.abe.fuzzy.large;

import de.upb.crypto.craco.abe.interfaces.BigIntegerAttribute;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.interfaces.*;
import de.upb.crypto.craco.common.interfaces.pe.PredicateEncryptionScheme;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Fuzzy IBE, Large Universe Construction from "Fuzzy Identity-Based Encryption"
 * by Sahai,Waters.
 *
 * @author Marius Dransfeld, refactoring: Fabian Eidens, Mirko Jürgens, Denis Diemert
 */
public class IBEFuzzySW05 extends AbstractIBEFuzzySW05 implements PredicateEncryptionScheme {

    public IBEFuzzySW05(IBEFuzzySW05PublicParameters pp) {
        this.pp = pp;
        this.zp = new Zp(pp.getGroupG1().size());
    }

    public IBEFuzzySW05(Representation repr) {
        this.pp = new IBEFuzzySW05PublicParameters(repr);
        this.zp = new Zp(pp.getGroupG1().size());
    }

    @Override
    public CipherText encrypt(PlainText plainText, EncryptionKey publicKey) {
        if (!(plainText instanceof GroupElementPlainText))
            throw new IllegalArgumentException("Not a valid plain text for this scheme");
        if (!(publicKey instanceof IBEFuzzySW05EncryptionKey))
            throw new IllegalArgumentException("Not a valid public key for this scheme");

        GroupElementPlainText pt = (GroupElementPlainText) plainText;
        IBEFuzzySW05EncryptionKey pk = (IBEFuzzySW05EncryptionKey) publicKey;

        ZpElement s = zp.getUniformlyRandomUnit();
        // Y^s = e (g1, g2)^s, for efficiency exponentiation pulled in group G_1
        GroupElement yToTheS = pp.getE().apply(pp.getG1().pow(s), pp.getG2());

        Identity omegaPrime = pk.getIdentity();
        // E' = m * Y^s
        GroupElement message = pt.get();
        GroupElement ePrime = message.op(yToTheS).compute();
        // E'' = g^s
        GroupElement eTwoPrime = pp.getG().pow(s).compute();
        Map<BigInteger, GroupElement> eElementMap = computeE(omegaPrime, s);

        return new IBEIBEFuzzySW05SW05CipherText(omegaPrime, ePrime, eTwoPrime, eElementMap);
    }

    @Override
    public PlainText decrypt(CipherText cipherText, DecryptionKey privateKey) {
        if (!(cipherText instanceof IBEIBEFuzzySW05SW05CipherText))
            throw new IllegalArgumentException("Invalid ciphertext for this scheme.");
        if (!(privateKey instanceof IBEFuzzySW05DecryptionKey))
            throw new IllegalArgumentException("Invalid private key for this scheme");

        IBEIBEFuzzySW05SW05CipherText ct = (IBEIBEFuzzySW05SW05CipherText) cipherText;
        IBEFuzzySW05DecryptionKey sk = (IBEFuzzySW05DecryptionKey) privateKey;

        Identity omega = sk.getIdentity();

        Map<BigInteger, GroupElement> rMap = sk.getRElementMap();
        Map<BigInteger, GroupElement> dMap = sk.getDElementMap();

        // get the intersection of omega and omegaPrime
        Set<BigIntegerAttribute> intersection = new HashSet<>(omega.getAttributes());
        intersection.retainAll(ct.getOmegaPrime().getAttributes());

        if (intersection.size() < pp.getIdentityThresholdD().intValue()) {
            throw new UnqualifiedKeyException("Not enough intersection, therefore decryption failed");
        }

        Set<BigIntegerAttribute> attributeSet = subset(intersection, pp.getIdentityThresholdD().intValue());
        GroupElement message = ct.getEPrime().op(restoreYs(ct, dMap, rMap, attributeSet).inv());

        return new GroupElementPlainText(message.compute());
    }

    @Override
    public PlainText getPlainText(Representation repr) {
        return new GroupElementPlainText(repr, pp.getGroupGT());
    }

    @Override
    public CipherText getCipherText(Representation repr) {
        return new IBEIBEFuzzySW05SW05CipherText(repr, pp);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        IBEFuzzySW05 other = (IBEFuzzySW05) o;
        return super.equals(other);
    }
}
