package de.upb.crypto.craco.ser.standalone.params;

import de.upb.crypto.craco.kem.asym.elgamal.ElgamalKEM;
import de.upb.crypto.craco.ser.standalone.StandaloneTestParams;
import de.upb.crypto.math.hash.HashFunction;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;
import de.upb.crypto.math.structures.groups.RingGroup;
import de.upb.crypto.math.structures.rings.zn.Zp;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;

public class ElgamalKEMParams {
    static String p =
            "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371";
    static String q = "F518AA8781A8DF278ABA4E7D64B7CB9D49462353";
    static String g =
            "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5";

    public static Collection<StandaloneTestParams> get() {
        /* generate field to define group */
        Zp zp = new Zp(new BigInteger(p, 16));

        /* multiplicative subgroup of field */
        RingGroup zpStar = RingGroup.unitGroupOf(zp);
;
        HashFunction md = new SHA256HashFunction();
        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();
        ElgamalKEM kem = new ElgamalKEM(zpStar, md);
        toReturn.add(new StandaloneTestParams(kem.getClass(), kem));
        return toReturn;
    }
}
