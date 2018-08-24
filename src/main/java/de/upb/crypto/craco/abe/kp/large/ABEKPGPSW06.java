package de.upb.crypto.craco.abe.kp.large;

import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.interfaces.CipherText;
import de.upb.crypto.craco.interfaces.DecryptionKey;
import de.upb.crypto.craco.interfaces.EncryptionKey;
import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.craco.interfaces.abe.SetOfAttributes;
import de.upb.crypto.craco.interfaces.pe.PredicateEncryptionScheme;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.util.Map;

/**
 * Key-Policy ABE Large Universe Construction.
 * <p>
 * <p>
 * Key-Policy Attribute Based Encryption (KP-ABE) is a generalization of Fuzzy IBE. It was first presented by Goyal et.
 * al. in [GPSW06]. Instead of the one threshold gate that Fuzzy IBE, presented in [SW05], uses as its implicit
 * Key-Policy, KP-ABE allows more flexible access structures to be used.
 * <p>
 * In Section 3.3.1 we present the small universe construction for access trees it allows allows access trees to be used
 * as the Key Policy.
 * <p>
 * <p>
 * [GPSW06] Vipul Goyal, Omkant Pandey, Amit Sahai, and Brent Waters. Attribute-based encryption for fine-grained access
 * control of encrypted data. In ACM Conference on Computer and Communications Security, pages 89–98. ACM, 2006.
 * <p>
 * SW05] Amit Sahai and Brent Waters. Fuzzy identity-based encryption. In Ronald Cramer, editor, Advances in Cryptology
 * – EUROCRYPT 2005, volume 3494 of Lecture Notes in Computer Science, pages 457–473. Springer Berlin Heidelberg, 2005.
 *
 * @author Marius Dransfeld, refactoring: Fabian Eidens
 */
public class ABEKPGPSW06 extends AbstractABEKPGPSW06 implements PredicateEncryptionScheme {

    public ABEKPGPSW06(ABEKPGPSW06PublicParameters kpp) {
        this.pp = kpp;
        this.zp = new Zp(pp.getGroupG1().size());
    }

    public ABEKPGPSW06(Representation repr) {
        this.pp = new ABEKPGPSW06PublicParameters(repr);
        this.zp = new Zp(pp.getGroupG1().size());
    }

    public CipherText encrypt(PlainText plainText, EncryptionKey publicKey) {
        if (!(plainText instanceof GroupElementPlainText))
            throw new IllegalArgumentException("Not a valid plain text for this encryption scheme.");
        if (!(publicKey instanceof ABEKPGPSW06EncryptionKey))
            throw new IllegalArgumentException("Not a valid public key for this encryption scheme.");

        GroupElementPlainText pt = (GroupElementPlainText) plainText;
        ABEKPGPSW06EncryptionKey pk = (ABEKPGPSW06EncryptionKey) publicKey;

        // Check the size validity of the attribute set
        SetOfAttributes attributes = pk.getAttributes();
        if (attributes.size() > pp.getN().intValue()) {
            throw new IllegalArgumentException(
                    "maximum attribute size is " + pp.getN() + ", but |omega| is " + attributes.size());
        }

        // s <- Z_p
        ZpElement s = zp.getUniformlyRandomUnit();
        // E' = m * Y^s \in GT
        GroupElement ePrime = pt.get().op(pp.getY().pow(s));
        // E'' = g^s \in G1
        GroupElement eTwoPrime = pp.getG1_generator().pow(s);
        // E_i = T(i)^s i \in omega
        Map<Attribute, GroupElement> eElementMap = restoreE(attributes, s);

        return new ABEKPGPSW06CipherText(ePrime, eTwoPrime, eElementMap, attributes);
    }

    @Override
    public PlainText decrypt(CipherText cipherText, DecryptionKey privateKey) {
        if (!(cipherText instanceof ABEKPGPSW06CipherText))
            throw new IllegalArgumentException("Not a valid cipher text for this scheme");
        if (!(privateKey instanceof ABEKPGPSW06DecryptionKey))
            throw new IllegalArgumentException("Not a valid private key for this scheme");

        ABEKPGPSW06CipherText ct = (ABEKPGPSW06CipherText) cipherText;
        ABEKPGPSW06DecryptionKey sk = (ABEKPGPSW06DecryptionKey) privateKey;

        // restore Z = Y^{-s}
        GroupElement zInv = restoreYs(sk, ct);

        return new GroupElementPlainText(ct.getEPrime().op(zInv.inv()));
    }

    @Override
    public PlainText getPlainText(Representation repr) {
        return new GroupElementPlainText(repr, pp.getGroupGT());
    }

    @Override
    public CipherText getCipherText(Representation repr) {
        return new ABEKPGPSW06CipherText(repr, pp);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof ABEKPGPSW06 && super.equals(o);
    }
}
