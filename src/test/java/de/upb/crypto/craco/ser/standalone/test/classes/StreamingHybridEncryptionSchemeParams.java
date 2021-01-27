package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.abe.cp.large.ABECPWat11Setup;
import de.upb.crypto.craco.enc.StreamingEncryptionScheme;
import de.upb.crypto.craco.enc.SymmetricKey;
import de.upb.crypto.craco.enc.sym.streaming.aes.StreamingGCMAESPacketMode;
import de.upb.crypto.craco.kem.HashBasedKeyDerivationFunction;
import de.upb.crypto.craco.kem.KeyEncapsulationMechanism;
import de.upb.crypto.craco.kem.StreamingHybridEncryptionScheme;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;
import de.upb.crypto.predenc.kem.abe.cp.large.ABECPWat11KEM;

public class StreamingHybridEncryptionSchemeParams {

    public static StandaloneTestParams get() {

        ABECPWat11Setup setup = new ABECPWat11Setup();

        // 80=SecrurityParameter, 5 = n = AttributeCount, l_max = 5 (max number
        // of lines in the MSP)
        setup.doKeyGen(80, 5, 5, false, true);

        KeyEncapsulationMechanism<SymmetricKey> kem = new SymmetricKeyPredicateKEM(
                new ABECPWat11KEM(setup.getPublicParameters()), new HashBasedKeyDerivationFunction());
        StreamingEncryptionScheme streamingAESGCMPacketMode = new StreamingGCMAESPacketMode();

        StreamingHybridEncryptionScheme hybridAESGCMPacketModeScheme = new StreamingHybridEncryptionScheme(
                streamingAESGCMPacketMode, kem);
        return new StandaloneTestParams(StreamingHybridEncryptionScheme.class, hybridAESGCMPacketModeScheme);
    }
}
