package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSPublicParameters;
import de.upb.crypto.craco.sig.ps.PSPublicParametersGen;
import de.upb.crypto.craco.sig.sps.eq.SPSEQPublicParameters;
import de.upb.crypto.craco.sig.sps.eq.SPSEQPublicParametersGen;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSignatureScheme;

import java.util.ArrayList;
import java.util.Collection;

public class SPSEQParams {

    public static Collection<StandaloneTestParams> get() {
        SPSEQPublicParameters pp;
        SPSEQPublicParametersGen ppSetup = new SPSEQPublicParametersGen();
        pp = ppSetup.generatePublicParameter(260, true);
        SPSEQSignatureScheme signatureScheme = new SPSEQSignatureScheme(pp);

        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();
        toReturn.add(new StandaloneTestParams(SPSEQSignatureScheme.class, signatureScheme));
        toReturn.add(new StandaloneTestParams(SPSEQPublicParameters.class, pp));
        return toReturn;
    }
}
