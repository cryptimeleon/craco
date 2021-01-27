package de.upb.crypto.craco.sig.hashthensign.params;

import de.upb.crypto.craco.sig.SignatureSchemeParams;
import de.upb.crypto.craco.sig.ps.PSSignatureSchemeTestParamGenerator;
import de.upb.crypto.math.hash.impl.VariableOutputLengthHashFunction;
import de.upb.crypto.math.hash.HashFunction;

import java.util.Arrays;
import java.util.Collection;

/**
 * Params for the {@link de.upb.crypto.craco.sig.ps.PSSignatureScheme} for testing its use in the
 * {@link de.upb.crypto.craco.sig.hashthensign.HashThenSign} construction.
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
