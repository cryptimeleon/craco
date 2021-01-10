package de.upb.crypto.craco.enc.test;

import de.upb.crypto.craco.common.interfaces.EncryptionScheme;
import de.upb.crypto.craco.common.interfaces.KeyPair;
import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalEncryption;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalPlainText;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalPrivateKey;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalPublicKey;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.structures.zn.Zn.ZnElement;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.function.Supplier;

public class ElgamalParams {
    public static TestParams getParams() {
        Zp zp = new Zp(BigInteger.valueOf(72973));
        Group zpGroup = zp.asAdditiveGroup();

        EncryptionScheme elgamalScheme = new ElgamalEncryption(zpGroup);

        Supplier<PlainText> supplier = () -> ((PlainText) new ElgamalPlainText(zpGroup.getUniformlyRandomElement()));

        KeyPair validKeyPair = ((ElgamalEncryption) elgamalScheme).generateKeyPair();

        ElgamalPublicKey validPK = (ElgamalPublicKey) validKeyPair.getPk();
        ElgamalPrivateKey validSK = (ElgamalPrivateKey) validKeyPair.getSk();

        ZnElement pow = validSK.getA().isOne() ? (ZnElement) zp.createZnElement(BigInteger.valueOf(5))
                : (ZnElement) zp.createZnElement(BigInteger.valueOf(1));
        ElgamalPrivateKey invalidSK = new ElgamalPrivateKey(zpGroup, validSK.getG(), pow);
        KeyPair invalidKeyPair = new KeyPair(validPK, invalidSK);

        return new TestParams(elgamalScheme, supplier, validKeyPair, invalidKeyPair);
    }
}
