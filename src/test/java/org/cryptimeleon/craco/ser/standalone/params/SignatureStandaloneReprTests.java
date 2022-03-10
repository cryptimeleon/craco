package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.sig.sps.agho11.SPSAGHO11PublicParameters;
import org.cryptimeleon.craco.sig.sps.agho11.SPSAGHO11PublicParametersGen;
import org.cryptimeleon.craco.sig.sps.agho11.SPSAGHO11SignatureScheme;
import org.cryptimeleon.craco.sig.sps.groth15.SPSGroth15PublicParameters;
import org.cryptimeleon.craco.sig.sps.groth15.SPSGroth15PublicParametersGen;
import org.cryptimeleon.craco.sig.sps.groth15.SPSGroth15SignatureScheme;
import org.cryptimeleon.craco.sig.sps.kpw15.SPSKPW15PublicParameterGen;
import org.cryptimeleon.craco.sig.sps.kpw15.SPSKPW15PublicParameters;
import org.cryptimeleon.craco.sig.sps.kpw15.SPSKPW15SignatureScheme;
import org.cryptimeleon.math.serialization.standalone.StandaloneReprSubTest;
import org.cryptimeleon.craco.sig.bbs.BBSBKeyGen;
import org.cryptimeleon.craco.sig.bbs.BBSBPublicParameter;
import org.cryptimeleon.craco.sig.bbs.BBSBSignatureScheme;
import org.cryptimeleon.craco.sig.hashthensign.HashThenSign;
import org.cryptimeleon.craco.sig.ps.PSExtendedSignatureScheme;
import org.cryptimeleon.craco.sig.ps.PSPublicParameters;
import org.cryptimeleon.craco.sig.ps.PSPublicParametersGen;
import org.cryptimeleon.craco.sig.ps.PSSignatureScheme;
import org.cryptimeleon.craco.sig.ps18.PS18ROMSignatureScheme;
import org.cryptimeleon.craco.sig.ps18.PS18SignatureScheme;
import org.cryptimeleon.craco.sig.sps.eq.SPSEQPublicParameters;
import org.cryptimeleon.craco.sig.sps.eq.SPSEQPublicParametersGen;
import org.cryptimeleon.craco.sig.sps.eq.SPSEQSignatureScheme;
import org.cryptimeleon.math.hash.impl.VariableOutputLengthHashFunction;

public class SignatureStandaloneReprTests extends StandaloneReprSubTest {
    private final PSPublicParameters pp = new PSPublicParametersGen().generatePublicParameter(128, true);

    public void testSPSEQ() {
        SPSEQPublicParameters pp = new SPSEQPublicParametersGen().generatePublicParameter(128, true);
        SPSEQSignatureScheme signatureScheme = new SPSEQSignatureScheme(pp);

        test(signatureScheme);
        test(pp);
    }

    public void testSPSGroth15() {
        SPSGroth15PublicParameters pp = new SPSGroth15PublicParametersGen().generatePublicParameter(128, SPSGroth15PublicParametersGen.Groth15Type.type1, 20, true);
        SPSGroth15SignatureScheme signatureScheme = new SPSGroth15SignatureScheme(pp);

        test(signatureScheme);
        test(pp);

        pp = new SPSGroth15PublicParametersGen().generatePublicParameter(128, SPSGroth15PublicParametersGen.Groth15Type.type2, 20,true);
        signatureScheme = new SPSGroth15SignatureScheme(pp);

        test(signatureScheme);
        test(pp);
    }

    public void testSPSAGHO11() {
        SPSAGHO11PublicParameters pp = SPSAGHO11PublicParametersGen.generatePublicParameters(128, true, new Integer[] {20,20});
        SPSAGHO11SignatureScheme scheme = new SPSAGHO11SignatureScheme(pp);

        test(scheme);
        test(pp);
    }

    public void testSPSKPW15() {
        SPSKPW15PublicParameters pp = new SPSKPW15PublicParameterGen().generatePublicParameter(128, true, 20);
        SPSKPW15SignatureScheme scheme = new SPSKPW15SignatureScheme(pp);

        test(scheme);
        test(pp);
    }

    public void testPS() {
        test(pp);
        test(new PSSignatureScheme(pp));
        test(new PSExtendedSignatureScheme(pp));
        test(new PS18ROMSignatureScheme(pp));
        test(new PS18SignatureScheme(pp));
        test(new HashThenSign(new VariableOutputLengthHashFunction((pp
                        .getZp().size().bitLength() - 1) / 8), new PSSignatureScheme(pp)));
    }

    public void testBBS() {
        BBSBKeyGen setup = new BBSBKeyGen();
        BBSBPublicParameter pp = setup.doKeyGen(80, true);
        test(pp);
        test(new BBSBSignatureScheme(pp));
    }
}
