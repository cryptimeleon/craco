package de.upb.crypto.craco.ser.test;

import de.upb.crypto.craco.abe.ibe.FullIdent;
import de.upb.crypto.craco.abe.ibe.FullIdentMasterSecret;
import de.upb.crypto.craco.abe.ibe.FullIdentPublicParameters;
import de.upb.crypto.craco.abe.ibe.FullIdentSetup;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.interfaces.CipherText;
import de.upb.crypto.craco.interfaces.DecryptionKey;
import de.upb.crypto.craco.interfaces.EncryptionKey;
import de.upb.crypto.craco.interfaces.PlainText;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

public class FullIdentParams {
    public static RepresentationTestParams getParams() {

        byte[] stringPlaintext;
        try {
            stringPlaintext = "keine Ahnung".getBytes("UTF-8");

            PlainText pt = new ByteArrayImplementation(stringPlaintext);

            FullIdentSetup setup = new FullIdentSetup();

            setup.doKeyGen(80, BigInteger.valueOf(stringPlaintext.length), true);

            FullIdentPublicParameters pp = setup.getPublicParameters();

            FullIdentMasterSecret msk = setup.getMasterSecret();

            FullIdent fi = new FullIdent(pp);

            ByteArrayImplementation identity = new ByteArrayImplementation("mirkoj@mail.upb.de".getBytes("UTF-8"));


            DecryptionKey privateKey = fi.generateDecryptionKey(msk, identity);
            EncryptionKey publicKey = fi.generateEncryptionKey(identity);

            CipherText ct = fi.encrypt(pt, publicKey);

            return new RepresentationTestParams(fi, publicKey, privateKey, pt, ct, msk);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }

    }
}
