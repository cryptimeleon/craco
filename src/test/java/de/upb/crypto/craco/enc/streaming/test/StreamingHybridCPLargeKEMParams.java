package de.upb.crypto.craco.enc.streaming.test;

import de.upb.crypto.craco.abe.cp.large.ABECPWat11;
import de.upb.crypto.craco.abe.cp.large.ABECPWat11MasterSecret;
import de.upb.crypto.craco.abe.cp.large.ABECPWat11PublicParameters;
import de.upb.crypto.craco.abe.cp.large.ABECPWat11Setup;
import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.abe.interfaces.StringAttribute;
import de.upb.crypto.craco.common.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.craco.common.policy.Policy;
import de.upb.crypto.craco.common.predicate.CiphertextIndex;
import de.upb.crypto.craco.enc.*;
import de.upb.crypto.craco.enc.sym.streaming.aes.StreamingCBCAES;
import de.upb.crypto.craco.enc.sym.streaming.aes.StreamingGCMAES;
import de.upb.crypto.craco.enc.sym.streaming.aes.StreamingGCMAESPacketMode;
import de.upb.crypto.craco.kem.HashBasedKeyDerivationFunction;
import de.upb.crypto.craco.kem.KeyEncapsulationMechanism;
import de.upb.crypto.craco.kem.StreamingHybridEncryptionScheme;
import de.upb.crypto.predenc.kem.abe.cp.large.ABECPWat11KEM;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class StreamingHybridCPLargeKEMParams {

    public static Collection<StreamingEncryptionSchemeParams> get() {
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

        EncryptionKey pk = largeScheme.generateEncryptionKey((CiphertextIndex) policy);

        SetOfAttributes validAttributes = new SetOfAttributes();
        validAttributes.add(new StringAttribute("A"));
        validAttributes.add(new StringAttribute("D"));
        validAttributes.add(new StringAttribute("E"));

        DecryptionKey validSK = largeScheme.generateDecryptionKey(msk, validAttributes);

        KeyPair keyPair = new KeyPair(pk, validSK);
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

        List<StreamingEncryptionSchemeParams> toReturn = new ArrayList<>();
        toReturn.add(new StreamingEncryptionSchemeParams(hybridAESGCMPacketModeScheme, keyPair));
        toReturn.add(new StreamingEncryptionSchemeParams(hybridAESGCMScheme, keyPair));
        toReturn.add(new StreamingEncryptionSchemeParams(hybridAESCBCScheme, keyPair));
        return toReturn;
    }

}
