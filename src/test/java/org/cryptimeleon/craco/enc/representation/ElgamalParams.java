package org.cryptimeleon.craco.enc.representation;

import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.enc.CipherText;
import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.craco.enc.EncryptionKey;
import org.cryptimeleon.craco.enc.KeyPair;
import org.cryptimeleon.craco.enc.asym.elgamal.ElgamalEncryption;
import org.cryptimeleon.craco.enc.asym.elgamal.ElgamalPlainText;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.rings.zn.Zp;

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
