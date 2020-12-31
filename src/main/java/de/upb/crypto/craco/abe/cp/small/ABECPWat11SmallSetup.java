package de.upb.crypto.craco.abe.cp.small;

import de.upb.crypto.craco.abe.interfaces.Attribute;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.pairings.counting.CountingBilinearGroup;
import de.upb.crypto.math.pairings.generic.BilinearGroup;
import de.upb.crypto.math.pairings.type1.supersingular.SupersingularTateGroupImpl;
import de.upb.crypto.math.structures.groups.lazy.LazyBilinearGroup;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class ABECPWat11SmallSetup {

    private ABECPWat11SmallPublicParameters pp;
    private ABECPWat11SmallMasterSecret msk;

    /**
     * Generate public parameters and the master secret.
     * <p>
     * Sets up public parameters and the master secret for a given security
     * parameter securityParameter. The universe specifies which attributes can
     * be used in the {@link ABECPWat11SmallEncryptionKey} and in the {@link ABECPWat11SmallDecryptionKey}.
     * <p>
     * To enable debugging modus, set debug to true. WARNING: This results in an
     * insecure instantiation of the underlying groups.
     *
     * @param securityParameter
     * @param universe          the universe of attributes
     * @param debug             - enable debugging.
     */
    public void doKeyGen(int securityParameter, Collection<? extends Attribute> universe, boolean debug) {
        BilinearGroup group;
        if (debug) {
            group = new CountingBilinearGroup(securityParameter, BilinearGroup.Type.TYPE_1);
        } else {
            group = new LazyBilinearGroup(new SupersingularTateGroupImpl(securityParameter));
        }

        doKeyGen(group, universe);
    }

    /**
     * Setup with pre-made group
     *
     * @param group    group to set up the scheme with
     * @param universe universe of attributes
     */
    public void doKeyGen(BilinearGroup group, Collection<? extends Attribute> universe) {
        // Public Parameter stuff
        pp = new ABECPWat11SmallPublicParameters();

        pp.setBilinearGroup(group);
        Zp zp = new Zp(pp.getGroupG1().size());

        ZpElement y = zp.getUniformlyRandomUnit();
        ZpElement a = zp.getUniformlyRandomUnit();

        // g in G_1
        pp.setG(pp.getGroupG1().getUniformlyRandomNonNeutral().compute());
        // Y = E (g, g)^y \in G_T
        pp.seteGGAlpha(pp.getE().apply(pp.getG(), pp.getG()).pow(y).compute());
        // g_a = g^a \in G_1
        pp.setgA(pp.getG().pow(a).compute());

        // msk = g^y
        msk = new ABECPWat11SmallMasterSecret(pp.getG().pow(y).compute());

        Map<Attribute, GroupElement> t = new HashMap<>();
        // \for all x in univese T_x = RandomNonNeutral in G1
        for (Attribute attribute : universe) {
            t.put(attribute, pp.getGroupG1().getUniformlyRandomNonNeutral().compute());
        }
        pp.setH(t);
    }

    public ABECPWat11SmallPublicParameters getPublicParameters() {
        return pp;
    }

    public ABECPWat11SmallMasterSecret getMasterSecret() {
        return msk;
    }
}
