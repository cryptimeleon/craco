package de.upb.crypto.craco.enc.params;

import de.upb.crypto.craco.abe.ibe.FullIdent;
import de.upb.crypto.craco.abe.ibe.FullIdentMasterSecret;
import de.upb.crypto.craco.abe.ibe.FullIdentPublicParameters;
import de.upb.crypto.craco.abe.ibe.FullIdentSetup;
import de.upb.crypto.craco.common.TestParameterProvider;
import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.EncryptionKey;
import de.upb.crypto.craco.common.interfaces.KeyPair;
import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.craco.enc.EncryptionSchemeTestParam;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class FullIdentParams implements TestParameterProvider {
    @Override
    public Object get() {
        FullIdentSetup setup = new FullIdentSetup();

        setup.doKeyGen(80, BigInteger.valueOf(1024), true);

        FullIdentPublicParameters pp = setup.getPublicParameters();

        FullIdentMasterSecret msk = setup.getMasterSecret();

        FullIdent fi = new FullIdent(pp);

        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[1024];
        random.nextBytes(randomBytes);
        PlainText plainText = new ByteArrayImplementation(randomBytes);

        ByteArrayImplementation identity = new ByteArrayImplementation(
                "mirkoj@mail.upb.de".getBytes(StandardCharsets.UTF_8)
        );

        DecryptionKey privateKey = fi.generateDecryptionKey(msk, identity);
        EncryptionKey publicKey = fi.generateEncryptionKey(identity);

        ByteArrayImplementation corruptedIdentity = new ByteArrayImplementation(
                "schuerma@mail.upb.de".getBytes(StandardCharsets.UTF_8)
        );
        DecryptionKey corruptedPrivateKey = fi.generateDecryptionKey(msk, corruptedIdentity);

        KeyPair validKeyPair = new KeyPair(publicKey, privateKey);
        KeyPair invalidKeyPair = new KeyPair(publicKey, corruptedPrivateKey);

        return new EncryptionSchemeTestParam(fi, plainText, validKeyPair, invalidKeyPair);
    }
}
