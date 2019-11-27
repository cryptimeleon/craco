package de.upb.crypto.craco.sig.ps18;

import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.interfaces.signature.SignatureKeyPair;

import static org.junit.Assert.assertTrue;

public class PS18PrecBenchmark {

    public static void main(String[] args) {
        long startTime;
        long endTime;
        long keygenTime;
        long signTime;

        long avgKeyGenTime = 0;
        long avgSignTime = 0;
        long avgVerifyTime = 0;
        long avgTotalTime = 0;

        int numMessages = 15;
        PS18SigSchemePerfTestParamGen paramGen = new PS18SigSchemePerfTestParamGen(80);
        PS18SignatureSchemePrec psScheme = paramGen.generateSigSchemePrec();
        MessageBlock message = paramGen.generateMessage(numMessages);
        SignatureKeyPair<? extends PS18VerificationKey, ? extends PS18SigningKey> keyPair;

        int runs = 10;
        int warmupRuns = 2;
        for (int i = 0; i < runs; ++i) {
            startTime = System.currentTimeMillis();

            keyPair = psScheme.generateKeyPair(numMessages);

            keygenTime = System.currentTimeMillis();

            PS18Signature signature = (PS18Signature) psScheme
                    .sign(message, keyPair.getSigningKey());

            signTime = System.currentTimeMillis();
            assertTrue(psScheme.verify(message, signature, keyPair.getVerificationKey()));

            endTime = System.currentTimeMillis();
            if (i >= warmupRuns) {
                System.out.println("------------------------------------------------------------");
                System.out.println("KEY GEN TIME: " + (keygenTime - startTime));
                System.out.println("SIGN TIME: " + (signTime - keygenTime));
                System.out.println("VERIFY TIME: " + (endTime - signTime));
                System.out.println("TOTAL TIME: " + (endTime - startTime));
                avgKeyGenTime += (keygenTime - startTime);
                avgSignTime += (signTime - keygenTime);
                avgVerifyTime += (endTime - signTime);
                avgTotalTime += (endTime - startTime);
                System.out.println("------------------------------------------------------------");
            }
        }
        avgKeyGenTime /= runs - warmupRuns;
        avgSignTime /= runs - warmupRuns;
        avgVerifyTime /= runs - warmupRuns;
        avgTotalTime /= runs - warmupRuns;
        System.out.println("AVERAGE KEY GEN TIME: " + avgKeyGenTime);
        System.out.println("AVERAGE SIGN TIME: " + avgSignTime);
        System.out.println("AVERAGE VERIFY TIME: " + avgVerifyTime);
        System.out.println("AVERAGE TOTAL TIME: " + avgTotalTime);
    }
}
