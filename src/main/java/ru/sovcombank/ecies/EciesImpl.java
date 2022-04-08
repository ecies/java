package ru.sovcombank.ecies;

import lombok.SneakyThrows;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collections;

public class EciesImpl implements Ecies {

    private static final String CURVE_NAME = "secp256k1";
    private static final int UNCOMPRESSED_PUBLIC_KEY_SIZE = 65;
    private static final int AES_IV_LENGTH = 16;
    private static final int AES_TAG_LENGTH = 16;
    private static final int AES_IV_PLUS_TAG_LENGTH = AES_IV_LENGTH + AES_TAG_LENGTH;
    private static final int SECRET_KEY_LENGTH = 32;
    private final SecureRandom random = new SecureRandom();

    @SneakyThrows
    public ECKeyPair generateEphemeralKey() {
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        g.initialize(ecSpec, random);
        KeyPair keyPair = g.generateKeyPair();
        return new ECKeyPair((ECPublicKey) keyPair.getPublic(), (ECPrivateKey) keyPair.getPrivate());
    }

    @SneakyThrows
    public String hexEncrypt(String plaintext, String peerPublicKey) {
        byte[] publicKey = Hex.decode(peerPublicKey);
        byte[] encrypt = encrypt(plaintext, publicKey);
        return Hex.toHexString(encrypt);
    }

    @SneakyThrows
    public String hexDecrypt(String ciphertext, String ownPrivateKey) {
        byte[] privateKey = Hex.decode(ownPrivateKey);
        byte[] cipherBytes = Hex.decode(ciphertext);
        return decrypt(cipherBytes, privateKey);
    }

    @SneakyThrows
    public byte[] encrypt(String plaintext, byte[] publicKeyBytes) {
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
        KeyPair pair = generateEphemeralKey(ecSpec);

        ECPrivateKey ephemeralPrivKey = (ECPrivateKey) pair.getPrivate();
        ECPublicKey ephemeralPubKey = (ECPublicKey) pair.getPublic();

        //generate receiver PK
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        org.bouncycastle.jce.spec.ECNamedCurveSpec curvedParams = new ECNamedCurveSpec(CURVE_NAME, ecSpec.getCurve(), ecSpec.getG(), ecSpec.getN());
        ECPublicKey publicKey = getEcPublicKey(curvedParams, publicKeyBytes, keyFactory);

        //Derive shared secret
        byte[] uncompressed = ephemeralPubKey.getQ().getEncoded(false);
        byte[] multiply = publicKey.getQ().multiply(ephemeralPrivKey.getD()).getEncoded(false);
        byte[] aesKey = hkdf(uncompressed, multiply);

        // AES encryption
        return aesEncrypt(plaintext, ephemeralPubKey, aesKey);
    }

    @SneakyThrows
    public String decrypt(byte[] cipherBytes, byte[] privateKeyBytes) {
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        org.bouncycastle.jce.spec.ECNamedCurveSpec curvedParams = new ECNamedCurveSpec(CURVE_NAME, ecSpec.getCurve(), ecSpec.getG(), ecSpec.getN());

        //generate receiver private key
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(new BigInteger(privateKeyBytes), curvedParams);
        org.bouncycastle.jce.interfaces.ECPrivateKey receiverPrivKey = (ECPrivateKey) keyFactory.generatePrivate(privateKeySpec);

        //get sender pub key
        byte[] senderPubKeyByte = Arrays.copyOf(cipherBytes, UNCOMPRESSED_PUBLIC_KEY_SIZE);
        ECPublicKey senderPubKey = getEcPublicKey(curvedParams, senderPubKeyByte, keyFactory);

        //decapsulate
        byte[] uncompressed = senderPubKey.getQ().getEncoded(false);
        byte[] multiply = senderPubKey.getQ().multiply(receiverPrivKey.getD()).getEncoded(false);
        byte[] aesKey = hkdf(uncompressed, multiply);

        // AES decryption
        byte[] decrypted = aesDecrypt(cipherBytes, aesKey);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    private byte[] aesEncrypt(String plaintext, ECPublicKey ephemeralPubKey, byte[] aesKey) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidCipherTextException {
        AESGCMBlockCipher aesgcmBlockCipher = new AESGCMBlockCipher();
        byte[] nonce = new byte[AES_IV_LENGTH];
        random.nextBytes(nonce);

        ParametersWithIV parametersWithIV = new ParametersWithIV(new KeyParameter(aesKey), nonce);
        aesgcmBlockCipher.init(true, parametersWithIV);

        byte[] input = plaintext.getBytes(StandardCharsets.UTF_8);
        int outputSize = aesgcmBlockCipher.getOutputSize(input.length);

        byte[] encrypted = new byte[outputSize];
        int pos = aesgcmBlockCipher.processBytes(input, 0, input.length, encrypted, 0);
        aesgcmBlockCipher.doFinal(encrypted, pos);

        byte[] tag = Arrays.copyOfRange(encrypted, encrypted.length - nonce.length, encrypted.length);
        encrypted = Arrays.copyOfRange(encrypted, 0, encrypted.length - tag.length);

        byte[] ephemeralPkUncompressed = ephemeralPubKey.getQ().getEncoded(false);
        return org.bouncycastle.util.Arrays.concatenate(ephemeralPkUncompressed, nonce, tag, encrypted);
    }

    private KeyPair generateEphemeralKey(ECNamedCurveParameterSpec ecSpec) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        g.initialize(ecSpec, random);
        return g.generateKeyPair();
    }

    private byte[] aesDecrypt(byte[] inputBytes, byte[] aesKey) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidCipherTextException {
        byte[] encrypted = Arrays.copyOfRange(inputBytes, UNCOMPRESSED_PUBLIC_KEY_SIZE, inputBytes.length);
        byte[] nonce = Arrays.copyOf(encrypted, AES_IV_LENGTH);
        byte[] tag = Arrays.copyOfRange(encrypted, AES_IV_LENGTH, AES_IV_PLUS_TAG_LENGTH);
        byte[] ciphered = Arrays.copyOfRange(encrypted, AES_IV_PLUS_TAG_LENGTH, encrypted.length);

        AESGCMBlockCipher aesgcmBlockCipher = new AESGCMBlockCipher();
        ParametersWithIV parametersWithIV = new ParametersWithIV(new KeyParameter(aesKey), nonce);
        aesgcmBlockCipher.init(false, parametersWithIV);

        int outputSize = aesgcmBlockCipher.getOutputSize(ciphered.length + tag.length);
        byte[] decrypted = new byte[outputSize];
        int pos = aesgcmBlockCipher.processBytes(ciphered, 0, ciphered.length, decrypted, 0);
        pos += aesgcmBlockCipher.processBytes(tag, 0, tag.length, decrypted, pos);
        aesgcmBlockCipher.doFinal(decrypted, pos);
        return decrypted;
    }

    private byte[] hkdf(byte[] uncompressed, byte[] multiply) {
        byte[] master = org.bouncycastle.util.Arrays.concatenate(uncompressed, multiply);
        HKDFBytesGenerator hkdfBytesGenerator = new HKDFBytesGenerator(new SHA256Digest());
        hkdfBytesGenerator.init(new HKDFParameters(master, null, null));
        byte[] aesKey = new byte[SECRET_KEY_LENGTH];
        hkdfBytesGenerator.generateBytes(aesKey, 0, aesKey.length);
        return aesKey;
    }

    private ECPublicKey getEcPublicKey(ECNamedCurveSpec curvedParams, byte[] senderPubKeyByte, KeyFactory keyFactory) throws InvalidKeySpecException {
        java.security.spec.ECPoint point = org.bouncycastle.jce.ECPointUtil.decodePoint(curvedParams.getCurve(), senderPubKeyByte);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, curvedParams);
        return (ECPublicKey) keyFactory.generatePublic(pubKeySpec);
    }
}
