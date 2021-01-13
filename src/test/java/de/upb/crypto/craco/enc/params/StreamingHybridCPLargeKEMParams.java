package de.upb.crypto.craco.enc.params;

import de.upb.crypto.craco.abe.cp.large.ABECPWat11;
import de.upb.crypto.craco.abe.cp.large.ABECPWat11MasterSecret;
import de.upb.crypto.craco.abe.cp.large.ABECPWat11PublicParameters;
import de.upb.crypto.craco.abe.cp.large.ABECPWat11Setup;
import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.abe.interfaces.StringAttribute;
import de.upb.crypto.craco.common.TestParameterProvider;
import de.upb.crypto.craco.common.interfaces.*;
import de.upb.crypto.craco.common.interfaces.pe.CiphertextIndex;
import de.upb.crypto.craco.common.interfaces.policy.Policy;
import de.upb.crypto.craco.common.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.craco.enc.EncryptionSchemeTestParam;
import de.upb.crypto.craco.enc.streaming.test.StreamingEncryptionSchemeParams;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.enc.sym.streaming.aes.StreamingCBCAES;
import de.upb.crypto.craco.enc.sym.streaming.aes.StreamingGCMAES;
import de.upb.crypto.craco.enc.sym.streaming.aes.StreamingGCMAESPacketMode;
import de.upb.crypto.craco.kem.HashBasedKeyDerivationFunction;
import de.upb.crypto.craco.kem.KeyEncapsulationMechanism;
import de.upb.crypto.craco.kem.StreamingHybridEncryptionScheme;
import de.upb.crypto.craco.kem.SymmetricKeyPredicateKEM;
import de.upb.crypto.craco.kem.abe.cp.large.ABECPWat11KEM;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class StreamingHybridCPLargeKEMParams implements TestParameterProvider {
    @Override
    public Object get() {
        ABECPWat11Setup setup = new ABECPWat11Setup();

        // 80=SecrurityParameter, 5 = n = AttributeCount, l_max = 5 (max number
        // of lines in the MSP)
        setup.doKeyGen(80, 5, 5, false, true);

        ABECPWat11PublicParameters publicParams = setup.getPublicParameters();
        ABECPWat11MasterSecret msk = setup.getMasterSecret();
        ABECPWat11 largeScheme = new ABECPWat11(publicParams);

        ThresholdPolicy leftNode = new ThresholdPolicy(1, new StringAttribute("A"), new StringAttribute("B"));

        ThresholdPolicy rightNode = new ThresholdPolicy(2, new StringAttribute("C"), new StringAttribute("D"),
                new StringAttribute("E"));

        Policy policy = new ThresholdPolicy(2, leftNode, rightNode);

        EncryptionKey pk = largeScheme.generateEncryptionKey(policy);

        SetOfAttributes validAttributes = new SetOfAttributes();
        validAttributes.add(new StringAttribute("A"));
        validAttributes.add(new StringAttribute("D"));
        validAttributes.add(new StringAttribute("E"));

        DecryptionKey validSK = largeScheme.generateDecryptionKey(msk, validAttributes);

        SetOfAttributes invalidAttributes = new SetOfAttributes();
        invalidAttributes.add(new StringAttribute("A"));
        DecryptionKey invalidSK = largeScheme.generateDecryptionKey(msk, invalidAttributes);

        KeyPair keyPair = new KeyPair(pk, validSK);
        KeyPair invalidKeyPair = new KeyPair(pk, invalidSK);
        StreamingEncryptionScheme streamingAESGCMPacketMode = new StreamingGCMAESPacketMode();
        StreamingEncryptionScheme streamingAESGCMScheme = new StreamingGCMAES();
        StreamingEncryptionScheme streamingAESCBCScheme = new StreamingCBCAES();
        KeyEncapsulationMechanism<SymmetricKey> kem = new SymmetricKeyPredicateKEM(new ABECPWat11KEM(publicParams),
                new HashBasedKeyDerivationFunction());

        StreamingHybridEncryptionScheme hybridAESGCMPacketModeScheme = new StreamingHybridEncryptionScheme(
                streamingAESGCMPacketMode, kem);
        StreamingHybridEncryptionScheme hybridAESGCMScheme = new StreamingHybridEncryptionScheme(streamingAESGCMScheme,
                kem);
        StreamingHybridEncryptionScheme hybridAESCBCScheme = new StreamingHybridEncryptionScheme(streamingAESCBCScheme,
                kem);

        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[1024];
        random.nextBytes(randomBytes);
        PlainText plainText = new ByteArrayImplementation(randomBytes);

        List<EncryptionSchemeTestParam> toReturn = new ArrayList<>();
        toReturn.add(new EncryptionSchemeTestParam(hybridAESGCMPacketModeScheme, plainText, keyPair, invalidKeyPair));
        toReturn.add(new EncryptionSchemeTestParam(hybridAESGCMScheme, plainText, keyPair, invalidKeyPair));
        toReturn.add(new EncryptionSchemeTestParam(hybridAESCBCScheme, plainText, keyPair, invalidKeyPair));
        return toReturn;
    }
}
