package de.upb.crypto.craco.sig.ps18;

import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.interfaces.signature.SignatureKeyPair;
import de.upb.crypto.craco.interfaces.signature.SigningKey;
import de.upb.crypto.craco.interfaces.signature.VerificationKey;
import de.upb.crypto.craco.sig.SignatureSchemeParams;
import de.upb.crypto.craco.sig.ps.PSPublicParameters;
import org.junit.Before;

public class PS18SigSchemeExprPerfTest {

    private PS18SignatureScheme psScheme;
    private SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> keyPair;
    private PSPublicParameters pp;
    private MessageBlock messageBlock;

    private PS18SignatureSchemeExpr psSchemeExpr;

    @Before
    public void setUp() {
        SignatureSchemeParams params = PS18SignatureSchemeTestParamGen
                .generateParams(160, 1);
        this.psScheme = (PS18SignatureScheme) params.getSignatureScheme();
        this.keyPair = params.getKeyPair1();
        this.pp = (PSPublicParameters) params.getPublicParameters();
        this.messageBlock = (MessageBlock) params.getMessage1();

        SignatureSchemeParams paramsExpr = PS18SignatureSchemeExprTestParamGen
                .generateParams(160, 1);
        this.psSchemeExpr = (PS18SignatureSchemeExpr) params.getSignatureScheme();
    }
}
