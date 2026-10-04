package com.example.auth;

import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;

public class EcdsaAuth {
    public void init() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        Signature sig = Signature.getInstance("SHA256withECDSA");
        Cipher tokenCipher = Cipher.getInstance("AES");
    }
}
