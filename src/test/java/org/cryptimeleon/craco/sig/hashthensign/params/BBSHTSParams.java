package org.cryptimeleon.craco.sig.hashthensign.params;

import org.cryptimeleon.craco.sig.SignatureSchemeParams;
import org.cryptimeleon.craco.sig.bbs.BBSBSignatureScheme;
import org.cryptimeleon.craco.sig.bbs.BBSSignatureSchemeTestParamGenerator;
import org.cryptimeleon.craco.sig.hashthensign.HashThenSign;
import org.cryptimeleon.math.hash.HashFunction;
import org.cryptimeleon.math.hash.impl.VariableOutputLengthHashFunction;

import java.util.Arrays;
import java.util.Collection;

/**
 * Params for the {@link BBSBSignatureScheme} for testing its use in the
 * {@link HashThenSign} construction.
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
