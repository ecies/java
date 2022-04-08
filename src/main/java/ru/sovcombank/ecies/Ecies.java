package ru.sovcombank.ecies;

import java.security.KeyPair;

public interface Ecies {

    ECKeyPair generateEphemeralKey();

    String hexEncrypt(String plaintext, String peerPublicKey);
    String hexDecrypt(String ciphertext, String ownPrivateKey);

    byte[] encrypt(String plaintext, byte[] publicKeyBytes);
    String decrypt(byte[] cipherBytes, byte[] privateKeyBytes);

}
