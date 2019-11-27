package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;
import de.upb.crypto.craco.sig.ps.PSPublicParameters;
import de.upb.crypto.craco.sig.ps.PSPublicParametersGen;
import de.upb.crypto.craco.sig.ps18.PS18SignatureSchemePrec;

import java.util.ArrayList;
import java.util.Collection;

public class PS18SignaturePrecParams {

    public static Collection<StandaloneTestParams> get() {

        PSPublicParameters pp;
        PSPublicParametersGen ppSetup = new PSPublicParametersGen();
        pp = ppSetup.generatePublicParameter(260, true);
        PS18SignatureSchemePrec signatureScheme = new PS18SignatureSchemePrec(pp);

        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();
        toReturn.add(new StandaloneTestParams(PS18SignatureSchemePrec.class, signatureScheme));
        return toReturn;
    }
}
