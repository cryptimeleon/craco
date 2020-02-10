package de.upb.crypto.craco.ser.test;

import de.upb.crypto.craco.common.interfaces.*;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalCipherText;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalEncryption;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalPlainText;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;

public class ElgamalParams {
    public static RepresentationTestParams getParams() {
        Zp zp = new Zp(BigInteger.valueOf(71));
        Group zpGroup = zp.asUnitGroup();

        EncryptionScheme elgamalScheme = new ElgamalEncryption(zpGroup);

        KeyPair validKeyPair = ((ElgamalEncryption) elgamalScheme).generateKeyPair();

        EncryptionKey validPK = validKeyPair.getPk();
        DecryptionKey validSK = validKeyPair.getSk();

        PlainText plaintext = new ElgamalPlainText(zpGroup.getUniformlyRandomElement());
        CipherText ciphertext = (ElgamalCipherText) elgamalScheme.encrypt(plaintext, validPK);

        return new RepresentationTestParams(elgamalScheme, validPK, validSK, plaintext, ciphertext, null);

    }
}
