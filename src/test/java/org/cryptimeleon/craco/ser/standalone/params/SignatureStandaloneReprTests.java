package org.cryptimeleon.craco.ser.standalone.params;

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
