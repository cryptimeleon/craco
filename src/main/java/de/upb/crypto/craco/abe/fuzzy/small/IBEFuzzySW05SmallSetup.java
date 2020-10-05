package de.upb.crypto.craco.abe.fuzzy.small;

import de.upb.crypto.craco.abe.fuzzy.large.Identity;
import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.factory.BilinearGroupFactory;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.math.BigInteger;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class IBEFuzzySW05SmallSetup {

    private IBEFuzzySW05SmallPublicParameters pp;
    private IBEFuzzySW05SmallMasterSecret msk;

    /**
     * Generates the master secret and the public parameters for a fuzzy
     * MSP based encryption scheme. The parameter n specifies the number of
     * attributes in an {@link Identity}. The parameter universeThreshold
     * specifies the required number of attributes in the intersection to
     * successfully decrypt a {@link PlainText}.
     * <p>
     * To enable debugging modus, set debug to true. WARNING: This results in an
     * insecure instantiation of the underlying groups.
     *
     * @param securityParameter
     * @param universeThreshold the required number of attributes in the intersection
     * @param debug             enable debugging
     */
    public void doKeyGen(int securityParameter, Collection<? extends Attribute> universe, BigInteger universeThreshold,
                         boolean debug) {
        // Public Parameter stuff
        BilinearGroupFactory fac = new BilinearGroupFactory(securityParameter);
        fac.setDebugMode(debug);
        fac.setRequirements(BilinearGroup.Type.TYPE_1, true, false, false);
        BilinearGroup group = fac.createBilinearGroup();

        doKeyGen(group, universe, universeThreshold);
    }

    /**
     * Setup with pre-made group
     *
     * @param group             group used in the scheme
     * @param universe          universe of attributes
     * @param universeThreshold required number of attributes in the intersection
     */
    public void doKeyGen(BilinearGroup group, Collection<? extends Attribute> universe, BigInteger universeThreshold) {
        // Public Parameter stuff
        pp = new IBEFuzzySW05SmallPublicParameters();
        pp.setBilinearGroup(group);

        Zp zp = new Zp(pp.getGroupG1().size());

        ZpElement y = zp.getUniformlyRandomUnit();

        // g in G_1
        pp.setG(pp.getGroupG1().getUniformlyRandomNonNeutral().compute());

        // Y = E (g, g)^y \in G_T
        pp.setY(pp.getE().apply(pp.getG(), pp.getG()).pow(y).compute());

        pp.setD(universeThreshold);
        Map<Attribute, GroupElement> t_map = new HashMap<>();

        Map<Attribute, ZpElement> t = new HashMap<>();

        // \for all x in univese T_x = g^t_x
        for (Attribute attribute : universe) {
            t.put(attribute, zp.getUniformlyRandomUnit());
            t_map.put(attribute, pp.getG().pow(t.get(attribute)).compute());
        }
        pp.setT(t_map);
        // msk =y , t_i
        msk = new IBEFuzzySW05SmallMasterSecret(y, t);
    }

    public IBEFuzzySW05SmallPublicParameters getPublicParameters() {
        return pp;
    }

    public IBEFuzzySW05SmallMasterSecret getMasterSecret() {
        return msk;
    }
}