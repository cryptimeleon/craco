package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;
import org.cryptimeleon.craco.sig.ps.PSPublicParameters;
import org.cryptimeleon.craco.sig.ps.PSPublicParametersGen;
import org.cryptimeleon.craco.sig.ps18.PS18ROMSignatureScheme;

import java.util.ArrayList;
import java.util.Collection;

public class PS18ROMSignatureParams {


    public static Collection<StandaloneTestParams> get() {

        PSPublicParameters pp;
        PSPublicParametersGen ppSetup = new PSPublicParametersGen();
        pp = ppSetup.generatePublicParameter(260, true);
        PS18ROMSignatureScheme signatureScheme = new PS18ROMSignatureScheme(pp);

        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();
        toReturn.add(new StandaloneTestParams(PS18ROMSignatureScheme.class, signatureScheme));
        return toReturn;
    }
}
