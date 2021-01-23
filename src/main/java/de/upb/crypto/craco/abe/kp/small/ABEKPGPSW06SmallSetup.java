package de.upb.crypto.craco.abe.kp.small;

import de.upb.crypto.craco.abe.interfaces.Attribute;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.structures.groups.counting.CountingBilinearGroup;
import de.upb.crypto.math.structures.groups.elliptic.BilinearGroup;
import de.upb.crypto.math.structures.groups.elliptic.type1.supersingular.SupersingularBilinearGroup;
import de.upb.crypto.math.structures.rings.zn.Zp;
import de.upb.crypto.math.structures.rings.zn.Zp.ZpElement;

import java.util.Collection;
import java.util.HashMap;

public class ABEKPGPSW06SmallSetup {

    private ABEKPGPSW06SmallPublicParameters pp;

    private ABEKPGPSW06SmallMasterSecret msk;

    /**
     * Generate public parameters and the master secret.
     * <p>
     * Sets up public parameters and the master secret for a given security
     * parameter securityParameter. The parameter universe specifies which
     * attributes can be used in the {@link ABEKPGPSW06SmallDecryptionKey} and in the
     * {@link ABEKPGPSW06SmallEncryptionKey}.
     * <p>
     * To enable debugging modus, set debug to true. WARNING: This results in an
     * insecure instantiation of the underlying groups.
     *
     * @param securityParameter
     * @param universe          - the attributes of the cipher text.
     * @param debug             - enable debugging.
     */
    public void doKeyGen(int securityParameter, Collection<? extends Attribute> universe, boolean debug) {
        BilinearGroup group;
        if (debug) {
            group = new CountingBilinearGroup(securityParameter, BilinearGroup.Type.TYPE_1);
        } else {
            group = new SupersingularBilinearGroup(securityParameter);
        }

        doKeyGen(group, universe);
    }

    public void doKeyGen(BilinearGroup group, Collection<? extends Attribute> universe) {
        // Public Parameter stuff
        pp = new ABEKPGPSW06SmallPublicParameters();
        pp.setBilinearGroup(group);

        Zp zp = new Zp(pp.getGroupG1().size());
        // set up the master secret
        ZpElement y = zp.getUniformlyRandomUnit();

        // g in G_1
        pp.setG(pp.getGroupG1().getUniformlyRandomNonNeutral().compute());
        // Y = E (g, g)^y \in G_T
        pp.setY(pp.getE().apply(pp.getG(), pp.getG()).pow(y).compute());

        // attribute in universe, t_i in Z_{size(g1)}
        HashMap<Attribute, ZpElement> t = new HashMap<Attribute, ZpElement>();
        // attribute in universe, T_i in G1
        HashMap<Attribute, GroupElement> T = new HashMap<Attribute, GroupElement>();

        for (Attribute attribute : universe) {
            ZpElement t_i = zp.getUniformlyRandomUnit();
            GroupElement T_i = pp.getG().pow(t_i);

            t.put(attribute, t_i);
            T.put(attribute, T_i.compute());
        }
        pp.setT(T);
        msk = new ABEKPGPSW06SmallMasterSecret(y, t);
    }

    public ABEKPGPSW06SmallPublicParameters getPublicParameters() {
        return pp;
    }

    public ABEKPGPSW06SmallMasterSecret getMasterSecret() {
        return msk;
    }
}
