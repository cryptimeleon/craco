package de.upb.crypto.craco.enc.test;

import de.upb.crypto.craco.abe.ibe.FullIdent;
import de.upb.crypto.craco.abe.ibe.FullIdentMasterSecret;
import de.upb.crypto.craco.abe.ibe.FullIdentPublicParameters;
import de.upb.crypto.craco.abe.ibe.FullIdentSetup;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.interfaces.DecryptionKey;
import de.upb.crypto.craco.interfaces.EncryptionKey;
import de.upb.crypto.craco.interfaces.KeyPair;
import de.upb.crypto.craco.interfaces.PlainText;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.function.Supplier;

public class FullIdentParams {

    public static TestParams getParams() {
        try {
            FullIdentSetup setup = new FullIdentSetup();

            setup.doKeyGen(80, BigInteger.valueOf(1024), true);

            FullIdentPublicParameters pp = setup.getPublicParameters();

            FullIdentMasterSecret msk = setup.getMasterSecret();

            FullIdent fi = new FullIdent(pp);

            Supplier<PlainText> supplier = new FullIdentSupplier();


            ByteArrayImplementation identity = new ByteArrayImplementation("mirkoj@mail.upb.de".getBytes("UTF-8"));

            DecryptionKey privateKey = fi.generateDecryptionKey(msk, identity);
            EncryptionKey publicKey = fi.generateEncryptionKey(identity);

            ByteArrayImplementation corruptedIdentity = new ByteArrayImplementation(
                    "schuerma@mail.upb.de".getBytes("UTF-8"));
            DecryptionKey corruptedPrivateKey = fi.generateDecryptionKey(msk, corruptedIdentity);

            KeyPair validKeyPair = new KeyPair(publicKey, privateKey);
            KeyPair invalidKeyPair = new KeyPair(publicKey, corruptedPrivateKey);

            return new TestParams(fi, supplier, validKeyPair, invalidKeyPair);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static class FullIdentSupplier implements Supplier<PlainText> {

        SecureRandom random = new SecureRandom();

        @Override
        public PlainText get() {
            byte[] toReturn = new byte[1024];
            random.nextBytes(toReturn);
            return new ByteArrayImplementation(toReturn);
        }

    }
}
