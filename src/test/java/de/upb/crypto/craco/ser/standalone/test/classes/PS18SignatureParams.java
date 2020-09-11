package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;
import de.upb.crypto.craco.sig.ps.PSPublicParameters;
import de.upb.crypto.craco.sig.ps.PSPublicParametersGen;
import de.upb.crypto.craco.sig.ps18.PS18SignatureScheme;

import java.util.ArrayList;
import java.util.Collection;

public class PS18SignatureParams {

    public static Collection<StandaloneTestParams> get() {

        PSPublicParameters pp;
        PSPublicParametersGen ppSetup = new PSPublicParametersGen();
        pp = ppSetup.generatePublicParameter(260, true);
        PS18SignatureScheme signatureScheme = new PS18SignatureScheme(pp);

        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();
        toReturn.add(new StandaloneTestParams(PS18SignatureScheme.class, signatureScheme));
        return toReturn;
    }
}
