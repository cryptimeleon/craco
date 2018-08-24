package de.upb.crypto.craco.interaction;

import java.security.Provider;

/**
 * {@link Provider} for all CrACo schemes.
 *
 * @author Marius Dransfeld, Fabian Eidens
 */
@SuppressWarnings("serial")
public class CrACoProvider extends Provider {
    public static final String IBE_NAME = "IBE";
    public static final String FUZZY_NAME = "Fuzzy";
    public static final String FUZZY_MSP_NAME = "FuzzyMSP";
    public static final String KP_ABE_SMALL_NAME = "KeyPolicyABESmall";
    public static final String KP_ABE_LARGE_NAME = "KeyPolicyABELarge";
    public static final String CP_ABE_SMALL_NAME = "CiphertextPolicyABESmall";
    public static final String CP_ABE_LARGE_NAME = "CiphertextPolicyABELarge";
    public static final String DIST_FUZZY_NAME = "DistributedFuzzy";
    public static final String DIST_KP_NAME = "DistributedKeyPolicy";
    public static final String DIST_CP_NAME = "DistributedCiphertextPolicy";
    public static final String FUZZY_FO_NAME = "FuzzyFujisakiOkamoto";
    public static final String CP_ABE_LARGE_FO_NAME = "CiphertextPolicyABELargeFujisakiOkamoto";
    public static final String KP_ABE_LARGE_FO_NAME = "KeyPolicyABELargeFujisakiOkamoto";
    public static final String CCA_CP_ABE_LARGE_YAMADA_NAME = "CCAKeyPolicyABELargeYamada";
    public static final String CP_AB_KEM_LARGE_NAME = "CiphertextPolicyABKEMLarge";
    public static final String KP_AB_KEM_LARGE_NAME = "KeyPolicyABKEMLarge";

    private static final String FUZZY_PACKAGE = "de.upb.crypto.pg.team2.fuzzy.jca";
    private static final String IBE_PACKAGE = "de.upb.crypto.pg.team2.ibe.jca";
    private static final String FUZZY_MSP_PACKAGE = "de.upb.crypto.pg.team2.fuzzymsp.jca";
    private static final String KP_ABE_SMALL_PACKAGE = "de.upb.crypto.pg.team2.abe.kp.small.jca";
    private static final String KP_ABE_LARGE_PACKAGE = "de.upb.crypto.pg.team2.abe.kp.large.jca";
    private static final String CP_ABE_SMALL_PACKAGE = "de.upb.crypto.pg.team2.abe.cp.small.jca";
    private static final String CP_ABE_LARGE_PACKAGE = "de.upb.crypto.pg.team2.abe.cp.large.jca";
    private static final String DIST_FUZZY_PACKAGE = "de.upb.crypto.pg.team2.fuzzy.distributed.jca";
    private static final String DIST_KP_PACKAGE = "de.upb.crypto.pg.team2.abe.kp.distributed.jca";
    public static final String FUZZY_FO_PACKAGE = "de.upb.crypto.pg.team2.fuzzy.fo";
    private static final String CP_ABE_LARGE_FO_PACKAGE = "de.upb.crypto.pg.team2.abe.cp.large.fo";
    private static final String KP_ABE_LARGE_FO_PACKAGE = "de.upb.crypto.pg.team2.abe.kp.large.fo";
    private static final String CCA_CP_ABE_LARGE_YAMADA_PACKAGE = "de.upb.crypto.craco.abe.cca.yamada";
    private static final String CP_AB_KEM_LARGE_PACKAGE = "de.upb.crypto.craco.abe.kem.cp.jca";
    private static final String KP_AB_KEM_LARGE_PACKAGE = "de.upb.crypto.craco.abe.kem.kp.jca";


    public CrACoProvider() {
        super("CrACo", 0.2, "Cryptographic Access Control for Large Scale Systems v0.2");

        addScheme(IBE_NAME, IBE_PACKAGE);
        addScheme(FUZZY_NAME, FUZZY_PACKAGE);
        addScheme(FUZZY_MSP_NAME, FUZZY_MSP_PACKAGE);
        addScheme(KP_ABE_SMALL_NAME, KP_ABE_SMALL_PACKAGE);
        addScheme(KP_ABE_LARGE_NAME, KP_ABE_LARGE_PACKAGE);
        addScheme(CP_ABE_SMALL_NAME, CP_ABE_SMALL_PACKAGE);
        addScheme(CP_ABE_LARGE_NAME, CP_ABE_LARGE_PACKAGE);
        addScheme(DIST_FUZZY_NAME, DIST_FUZZY_PACKAGE);
        addScheme(DIST_KP_NAME, DIST_KP_PACKAGE);
        addScheme(FUZZY_FO_NAME, FUZZY_FO_PACKAGE);
        addScheme(CP_ABE_LARGE_FO_NAME, CP_ABE_LARGE_FO_PACKAGE);
        addScheme(KP_ABE_LARGE_FO_NAME, KP_ABE_LARGE_FO_PACKAGE);
        addScheme(CP_AB_KEM_LARGE_NAME, CP_AB_KEM_LARGE_PACKAGE);
        addScheme(KP_AB_KEM_LARGE_NAME, KP_AB_KEM_LARGE_PACKAGE);

        // Advanced Constructions
//		addScheme(CCA_CP_ABE_LARGE_YAMADA_NAME, CCA_CP_ABE_LARGE_YAMADA_PACKAGE);
        put("Cipher." + CCA_CP_ABE_LARGE_YAMADA_NAME, CCA_CP_ABE_LARGE_YAMADA_PACKAGE + ".YamadaCCACPABECipher");
        put("KeyPairGenerator." + CCA_CP_ABE_LARGE_YAMADA_NAME, CCA_CP_ABE_LARGE_YAMADA_PACKAGE + ".KeyPairGenerator");
        put("AlgorithmParameters." + CCA_CP_ABE_LARGE_YAMADA_NAME, CCA_CP_ABE_LARGE_YAMADA_PACKAGE + ".Parameters");
        put("AlgorithmParameterGenerator." + CCA_CP_ABE_LARGE_YAMADA_NAME, CCA_CP_ABE_LARGE_YAMADA_PACKAGE +
                ".ParameterGenerator");
    }

    private void addScheme(String name, String packageName) {
        put("Cipher." + name, packageName + ".Cipher");
        put("KeyPairGenerator." + name, packageName + ".KeyPairGenerator");
        put("AlgorithmParameters." + name, packageName + ".Parameters");
        put("AlgorithmParameterGenerator." + name, packageName + ".ParameterGenerator");
    }
}
