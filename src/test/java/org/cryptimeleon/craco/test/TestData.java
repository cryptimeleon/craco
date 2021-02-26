package org.cryptimeleon.craco.test;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.common.plaintexts.RingElementPlainText;
import org.cryptimeleon.craco.enc.*;
import org.cryptimeleon.craco.enc.asym.elgamal.ElgamalEncryption;
import org.cryptimeleon.craco.sig.Signature;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.SigningKey;
import org.cryptimeleon.craco.sig.VerificationKey;
import org.cryptimeleon.craco.sig.ps.*;
import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.StandaloneRepresentable;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zn;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.math.BigInteger;
import java.util.*;

public class TestData implements Representable {

    @Represented
    BigInteger bigInt;

    @Represented
    String string;

    @Represented
    Integer integer;

    @Represented
    byte[] bytes;

    @Represented
    Boolean bool;

    @Represented
    StandaloneRepresentable representable;

    @Represented
    Group group;

    @Represented(restorer = "group")
    GroupElement element;

    @Represented
    EncryptionScheme encryptionScheme;

    @Represented(restorer = "encryptionScheme")
    EncryptionKey encryptionKey;

    @Represented(restorer = "encryptionScheme")
    DecryptionKey decryptionKey;

    @Represented(restorer = "encryptionScheme")
    PlainText plaintext;

    @Represented(restorer = "encryptionScheme")
    CipherText ciphertext;

    @Represented
    PSSignatureScheme signatureScheme;

    @Represented(restorer = "signatureScheme")
    Signature signature;

    @Represented(restorer = "signatureScheme")
    SigningKey singingKey;

    @Represented(restorer = "signatureScheme")
    VerificationKey verificationKey;

    @Represented(restorer = "int -> group")
    LinkedHashMap<BigInteger, GroupElement> map;

    @Represented(restorer = "[group]")
    List<GroupElement> list;

    @Represented(restorer = "[group]")
    GroupElement[] array;

    @Represented(restorer = "int -> (bigint -> group)")
    private HashMap<Integer, LinkedHashMap<BigInteger, GroupElement>> t_function;

    @Represented(restorer = "int -> [group]")
    private HashMap<Integer, LinkedList<GroupElement>> t_functionWithList;

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public TestData() {
        bigInt = BigInteger.valueOf(3);
        string = "hierkennteIhreWerbungstehen";
        integer = 2;
        bytes = new byte[]{-2, 3, 5};
        bool = false;
        representable = new Zn(BigInteger.valueOf(5));
        group = new Zp(BigInteger.valueOf(13)).asAdditiveGroup();
        element = group.getNeutralElement();
        encryptionScheme = new ElgamalEncryption(group);
        KeyPair kp = ((ElgamalEncryption) encryptionScheme).generateKeyPair();
        encryptionKey = kp.getPk();
        decryptionKey = kp.getSk();
        map = new LinkedHashMap<>();
        for (int i = 0; i < 5; i++) {
            map.put(BigInteger.valueOf(i), group.getUniformlyRandomElement());
        }
        list = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            list.add(group.getUniformlyRandomElement());
        }
        plaintext = new GroupElementPlainText(group.getUniformlyRandomElement());
        ciphertext = encryptionScheme.encrypt(plaintext, encryptionKey);
        PSPublicParametersGen ppSetup = new PSPublicParametersGen();
        PSPublicParameters pp = ppSetup.generatePublicParameter(160, true);
        signatureScheme = new PSSignatureScheme(pp);
        SignatureKeyPair<? extends PSVerificationKey, ? extends PSSigningKey> keyPair =
                signatureScheme.generateKeyPair(1);
        verificationKey = keyPair.getVerificationKey();
        singingKey = keyPair.getSigningKey();
        MessageBlock sigPt = new MessageBlock(new RingElementPlainText(pp.getZp().getUniformlyRandomElement()));
        signature = signatureScheme.sign(sigPt, singingKey);
        t_function = new HashMap<>();
        t_functionWithList = new HashMap<>();
        for (int i = 0; i < 20; i++) {
            LinkedHashMap<Integer, GroupElement> inner = new LinkedHashMap<>();
            for (int j = 0; j < 10; j++) {
                inner.put(j, group.getUniformlyRandomElement());
            }
            t_function.put(i, map);
            t_functionWithList.put(i, new LinkedList<>(map.values()));
        }
        array = new GroupElement[42];
        for (int i = 0; i < 42; i++) {
            array[i] = group.getUniformlyRandomElement();
        }
    }

    public TestData(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public String toString() {
        return "TestData [bigInt=" + bigInt + ", string=" + string + ", integer=" + integer + ", bytes="
                + Arrays.toString(bytes) + ", bool=" + bool + ", representable=" + representable + ", group=" + group
                + ", element=" + element + ", encryptionScheme=" + encryptionScheme + ", encryptionKey=" + encryptionKey
                + ", decryptionKey=" + decryptionKey + ", plaintext=" + plaintext + ", ciphertext=" + ciphertext
                + ", signatureScheme=" + signatureScheme + ", signature=" + signature + ", singingKey=" + singingKey
                + ", verificationKey=" + verificationKey + ", map=" + map + ", list=" + list + ", t_function="
                + t_function + "]";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((bigInt == null) ? 0 : bigInt.hashCode());
        result = prime * result + (bool ? 1231 : 1237);
        result = prime * result + Arrays.hashCode(bytes);
        result = prime * result + ((ciphertext == null) ? 0 : ciphertext.hashCode());
        result = prime * result + ((decryptionKey == null) ? 0 : decryptionKey.hashCode());
        result = prime * result + ((element == null) ? 0 : element.hashCode());
        result = prime * result + ((encryptionKey == null) ? 0 : encryptionKey.hashCode());
        result = prime * result + ((encryptionScheme == null) ? 0 : encryptionScheme.hashCode());
        result = prime * result + ((group == null) ? 0 : group.hashCode());
        result = prime * result + integer;
        result = prime * result + ((list == null) ? 0 : list.hashCode());
        result = prime * result + ((map == null) ? 0 : map.hashCode());
        result = prime * result + ((plaintext == null) ? 0 : plaintext.hashCode());
        result = prime * result + ((representable == null) ? 0 : representable.hashCode());
        result = prime * result + ((signature == null) ? 0 : signature.hashCode());
        result = prime * result + ((signatureScheme == null) ? 0 : signatureScheme.hashCode());
        result = prime * result + ((singingKey == null) ? 0 : singingKey.hashCode());
        result = prime * result + ((string == null) ? 0 : string.hashCode());
        result = prime * result + ((t_function == null) ? 0 : t_function.hashCode());
        result = prime * result + ((verificationKey == null) ? 0 : verificationKey.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        TestData other = (TestData) obj;
        if (bigInt == null) {
            if (other.bigInt != null)
                return false;
        } else if (!bigInt.equals(other.bigInt))
            return false;
        if (bool != other.bool)
            return false;
        if (!Arrays.equals(bytes, other.bytes))
            return false;
        if (ciphertext == null) {
            if (other.ciphertext != null)
                return false;
        } else if (!ciphertext.equals(other.ciphertext))
            return false;
        if (decryptionKey == null) {
            if (other.decryptionKey != null)
                return false;
        } else if (!decryptionKey.equals(other.decryptionKey))
            return false;
        if (element == null) {
            if (other.element != null)
                return false;
        } else if (!element.equals(other.element))
            return false;
        if (encryptionKey == null) {
            if (other.encryptionKey != null)
                return false;
        } else if (!encryptionKey.equals(other.encryptionKey))
            return false;
        if (encryptionScheme == null) {
            if (other.encryptionScheme != null)
                return false;
        } else if (!encryptionScheme.equals(other.encryptionScheme))
            return false;
        if (group == null) {
            if (other.group != null)
                return false;
        } else if (!group.equals(other.group))
            return false;
        if (integer != other.integer)
            return false;
        if (list == null) {
            if (other.list != null)
                return false;
        } else if (!list.equals(other.list))
            return false;
        if (map == null) {
            if (other.map != null)
                return false;
        } else if (!map.equals(other.map))
            return false;
        if (plaintext == null) {
            if (other.plaintext != null)
                return false;
        } else if (!plaintext.equals(other.plaintext))
            return false;
        if (representable == null) {
            if (other.representable != null)
                return false;
        } else if (!representable.equals(other.representable))
            return false;
        if (signature == null) {
            if (other.signature != null)
                return false;
        } else if (!signature.equals(other.signature))
            return false;
        if (signatureScheme == null) {
            if (other.signatureScheme != null)
                return false;
        } else if (!signatureScheme.equals(other.signatureScheme))
            return false;
        if (singingKey == null) {
            if (other.singingKey != null)
                return false;
        } else if (!singingKey.equals(other.singingKey))
            return false;
        if (string == null) {
            if (other.string != null)
                return false;
        } else if (!string.equals(other.string))
            return false;
        if (t_function == null) {
            if (other.t_function != null)
                return false;
        } else if (!t_function.equals(other.t_function))
            return false;
        if (verificationKey == null) {
            if (other.verificationKey != null)
                return false;
        } else if (!verificationKey.equals(other.verificationKey))
            return false;
        return true;
    }

}