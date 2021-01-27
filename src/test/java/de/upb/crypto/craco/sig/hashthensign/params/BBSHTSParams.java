package de.upb.crypto.craco.sig.hashthensign.params;

import de.upb.crypto.craco.sig.SignatureSchemeParams;
import de.upb.crypto.craco.sig.bbs.BBSSignatureSchemeTestParamGenerator;
import de.upb.crypto.math.hash.impl.VariableOutputLengthHashFunction;
import de.upb.crypto.math.hash.HashFunction;

import java.util.Arrays;
import java.util.Collection;

/**
 * Params for the {@link de.upb.crypto.craco.sig.bbs.BBSBSignatureScheme} for testing its use in the
 * {@link de.upb.crypto.craco.sig.hashthensign.HashThenSign} construction.
 */
public class BBSHTSParams {
    public static Collection<HashThenSignParams> getParams() {
        SignatureSchemeParams params = BBSSignatureSchemeTestParamGenerator.generateParams(80);
        // Note that HashThenSign does not work with every hash function
        HashFunction hashFunction = new VariableOutputLengthHashFunction(params.getSignatureScheme()
                .getMaxNumberOfBytesForMapToPlaintext());

        return Arrays.asList(
                new HashThenSignParams(params, hashFunction)
        );
    }
}
