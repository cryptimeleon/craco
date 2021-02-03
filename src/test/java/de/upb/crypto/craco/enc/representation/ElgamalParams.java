package de.upb.crypto.craco.enc.representation;

import de.upb.crypto.craco.common.plaintexts.PlainText;
import de.upb.crypto.craco.enc.CipherText;
import de.upb.crypto.craco.enc.DecryptionKey;
import de.upb.crypto.craco.enc.EncryptionKey;
import de.upb.crypto.craco.enc.KeyPair;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalEncryption;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalPlainText;
import de.upb.crypto.math.structures.groups.Group;
import de.upb.crypto.math.structures.rings.zn.Zp;

import java.math.BigInteger;

public class ElgamalParams {
    public static RepresentationTestParams getParams() {
        Zp zp = new Zp(BigInteger.valueOf(71));
        Group zpGroup = zp.asUnitGroup();

        ElgamalEncryption elgamalScheme = new ElgamalEncryption(zpGroup);

        KeyPair validKeyPair = elgamalScheme.generateKeyPair();

        EncryptionKey validPK = validKeyPair.getPk();
        DecryptionKey validSK = validKeyPair.getSk();

        PlainText plaintext = new ElgamalPlainText(zpGroup.getUniformlyRandomElement());
        CipherText ciphertext = elgamalScheme.encrypt(plaintext, validPK);

        return new RepresentationTestParams(elgamalScheme, validPK, validSK, plaintext, ciphertext);
    }
}
