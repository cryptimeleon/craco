package org.cryptimeleon.craco.sig.hashthensign.params;

import org.cryptimeleon.craco.sig.SignatureSchemeParams;
import org.cryptimeleon.craco.sig.hashthensign.HashThenSign;
import org.cryptimeleon.craco.sig.ps.PSSignatureScheme;
import org.cryptimeleon.craco.sig.ps.PSSignatureSchemeTestParamGenerator;
import org.cryptimeleon.math.hash.HashFunction;
import org.cryptimeleon.math.hash.impl.VariableOutputLengthHashFunction;

import java.util.Arrays;
import java.util.Collection;

/**
 * Params for the {@link PSSignatureScheme} for testing its use in the
 * {@link HashThenSign} construction.
 */
public class PSHTSParams {
    public static Collection<HashThenSignParams> getParams() {
        SignatureSchemeParams params = PSSignatureSchemeTestParamGenerator.generateParams(160, 2);
        // Note that HashThenSign does not work with every hash function
        HashFunction hashFunction = new VariableOutputLengthHashFunction(params.getSignatureScheme()
                .getMaxNumberOfBytesForMapToPlaintext());

        return Arrays.asList(
                new HashThenSignParams(params, hashFunction)
        );
    }
}
