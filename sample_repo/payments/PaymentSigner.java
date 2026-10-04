package com.example.payments;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import javax.crypto.Cipher;

public class PaymentSigner {
    public KeyPair newKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public byte[] sign(KeyPair kp, byte[] msg) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        return signer.sign();
    }

    public Cipher legacyCardVault() throws Exception {
        return Cipher.getInstance("DESede/ECB/PKCS5Padding");
    }
}
