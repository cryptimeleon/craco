package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;
import org.cryptimeleon.craco.sig.ps.PSExtendedSignatureScheme;
import org.cryptimeleon.craco.sig.ps.PSPublicParameters;
import org.cryptimeleon.craco.sig.ps.PSPublicParametersGen;

import java.util.ArrayList;
import java.util.Collection;

public class PSSignatureParams {

    public static Collection<StandaloneTestParams> get() {

        PSPublicParameters pp;
        PSPublicParametersGen ppSetup = new PSPublicParametersGen();
        pp = ppSetup.generatePublicParameter(260, true);
        PSExtendedSignatureScheme signatureScheme = new PSExtendedSignatureScheme(pp);

        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();
        toReturn.add(new StandaloneTestParams(PSExtendedSignatureScheme.class, signatureScheme));
        return toReturn;
    }
}
