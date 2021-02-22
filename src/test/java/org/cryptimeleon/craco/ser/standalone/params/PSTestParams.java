package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;
import org.cryptimeleon.craco.sig.hashthensign.HashThenSign;
import org.cryptimeleon.craco.sig.ps.PSPublicParameters;
import org.cryptimeleon.craco.sig.ps.PSPublicParametersGen;
import org.cryptimeleon.craco.sig.ps.PSSignatureScheme;
import org.cryptimeleon.math.hash.impl.VariableOutputLengthHashFunction;

import java.util.ArrayList;
import java.util.Collection;

public class PSTestParams {

    public static Collection<StandaloneTestParams> get() {
        PSPublicParametersGen ppSetup = new PSPublicParametersGen();
        PSPublicParameters pp = ppSetup.generatePublicParameter(160, true);

        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();
        toReturn.add(new StandaloneTestParams(PSPublicParameters.class, pp));
        toReturn.add(new StandaloneTestParams(PSSignatureScheme.class, new PSSignatureScheme(pp)));
        toReturn.add(new StandaloneTestParams(HashThenSign.class,
                new HashThenSign(new VariableOutputLengthHashFunction((pp
                        .getZp().size().bitLength() - 1) / 8), new PSSignatureScheme(pp))));
        return toReturn;
    }
}
