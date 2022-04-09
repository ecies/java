package ecies;

import ecies.common.AESGCMBlockCipher;
import ecies.common.ECKeyPair;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

@UtilityClass
public class Ecies {

    private static final String CURVE_NAME = "secp256k1";
    private static final int UNCOMPRESSED_PUBLIC_KEY_SIZE = 65;
    private static final int AES_IV_LENGTH = 16;
    private static final int AES_TAG_LENGTH = 16;
    private static final int AES_IV_PLUS_TAG_LENGTH = AES_IV_LENGTH + AES_TAG_LENGTH;
    private static final int SECRET_KEY_LENGTH = 32;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @SneakyThrows
    public static ECKeyPair generateEcKeyPair() {
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        g.initialize(ecSpec, SECURE_RANDOM);
        KeyPair keyPair = g.generateKeyPair();
        return new ECKeyPair((ECPublicKey) keyPair.getPublic(), (ECPrivateKey) keyPair.getPrivate());
    }

    @SneakyThrows
    public static String encrypt(String publicKeyHex, String message) {
        byte[] publicKey = Hex.decode(publicKeyHex);
        byte[] encrypt = encrypt(publicKey, message.getBytes(StandardCharsets.UTF_8));
        return Hex.toHexString(encrypt);
    }

    @SneakyThrows
    public static String decrypt(String privateKeyHex, String ciphertext) {
        byte[] privateKey = Hex.decode(privateKeyHex);
        byte[] cipherBytes = Hex.decode(ciphertext);
        return new String(decrypt(privateKey, cipherBytes), StandardCharsets.UTF_8);
    }

    @SneakyThrows
    public static byte[] encrypt(byte[] publicKeyBytes, byte[] message) {
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
        KeyPair pair = generateEphemeralKey(ecSpec);

        ECPrivateKey ephemeralPrivKey = (ECPrivateKey) pair.getPrivate();
        ECPublicKey ephemeralPubKey = (ECPublicKey) pair.getPublic();

        //generate receiver PK
        KeyFactory keyFactory = getKeyFactory();
        org.bouncycastle.jce.spec.ECNamedCurveSpec curvedParams = new ECNamedCurveSpec(CURVE_NAME, ecSpec.getCurve(), ecSpec.getG(), ecSpec.getN());
        ECPublicKey publicKey = getEcPublicKey(curvedParams, publicKeyBytes, keyFactory);

        //Derive shared secret
        byte[] uncompressed = ephemeralPubKey.getQ().getEncoded(false);
        byte[] multiply = publicKey.getQ().multiply(ephemeralPrivKey.getD()).getEncoded(false);
        byte[] aesKey = hkdf(uncompressed, multiply);

        // AES encryption
        return aesEncrypt(message, ephemeralPubKey, aesKey);
    }

    private static KeyFactory getKeyFactory() throws NoSuchAlgorithmException {
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        return keyFactory;
    }

    @SneakyThrows
    public static byte[] decrypt(byte[] privateKeyBytes, byte[] cipherBytes) {
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
        KeyFactory keyFactory = getKeyFactory();
        org.bouncycastle.jce.spec.ECNamedCurveSpec curvedParams = new ECNamedCurveSpec(CURVE_NAME, ecSpec.getCurve(), ecSpec.getG(), ecSpec.getN());

        //generate receiver private key
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(new BigInteger(1, privateKeyBytes), curvedParams);
        org.bouncycastle.jce.interfaces.ECPrivateKey receiverPrivKey = (ECPrivateKey) keyFactory.generatePrivate(privateKeySpec);

        //get sender pub key
        byte[] senderPubKeyByte = Arrays.copyOf(cipherBytes, UNCOMPRESSED_PUBLIC_KEY_SIZE);
        ECPublicKey senderPubKey = getEcPublicKey(curvedParams, senderPubKeyByte, keyFactory);

        //decapsulate
        byte[] uncompressed = senderPubKey.getQ().getEncoded(false);
        byte[] multiply = senderPubKey.getQ().multiply(receiverPrivKey.getD()).getEncoded(false);
        byte[] aesKey = hkdf(uncompressed, multiply);

        // AES decryption
        return aesDecrypt(cipherBytes, aesKey);
    }

    private static byte[] aesEncrypt(byte[] message, ECPublicKey ephemeralPubKey, byte[] aesKey) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidCipherTextException {
        AESGCMBlockCipher aesgcmBlockCipher = new AESGCMBlockCipher();
        byte[] nonce = new byte[AES_IV_LENGTH];
        SECURE_RANDOM.nextBytes(nonce);

        ParametersWithIV parametersWithIV = new ParametersWithIV(new KeyParameter(aesKey), nonce);
        aesgcmBlockCipher.init(true, parametersWithIV);

        int outputSize = aesgcmBlockCipher.getOutputSize(message.length);

        byte[] encrypted = new byte[outputSize];
        int pos = aesgcmBlockCipher.processBytes(message, 0, message.length, encrypted, 0);
        aesgcmBlockCipher.doFinal(encrypted, pos);

        byte[] tag = Arrays.copyOfRange(encrypted, encrypted.length - nonce.length, encrypted.length);
        encrypted = Arrays.copyOfRange(encrypted, 0, encrypted.length - tag.length);

        byte[] ephemeralPkUncompressed = ephemeralPubKey.getQ().getEncoded(false);
        return org.bouncycastle.util.Arrays.concatenate(ephemeralPkUncompressed, nonce, tag, encrypted);
    }

    private KeyPair generateEphemeralKey(ECNamedCurveParameterSpec ecSpec) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        g.initialize(ecSpec, SECURE_RANDOM);
        return g.generateKeyPair();
    }

    private static byte[] aesDecrypt(byte[] inputBytes, byte[] aesKey) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidCipherTextException {
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

    private static byte[] hkdf(byte[] uncompressed, byte[] multiply) {
        byte[] master = org.bouncycastle.util.Arrays.concatenate(uncompressed, multiply);
        HKDFBytesGenerator hkdfBytesGenerator = new HKDFBytesGenerator(new SHA256Digest());
        hkdfBytesGenerator.init(new HKDFParameters(master, null, null));
        byte[] aesKey = new byte[SECRET_KEY_LENGTH];
        hkdfBytesGenerator.generateBytes(aesKey, 0, aesKey.length);
        return aesKey;
    }

    private static ECPublicKey getEcPublicKey(ECNamedCurveSpec curvedParams, byte[] senderPubKeyByte, KeyFactory keyFactory) throws InvalidKeySpecException {
        java.security.spec.ECPoint point = org.bouncycastle.jce.ECPointUtil.decodePoint(curvedParams.getCurve(), senderPubKeyByte);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, curvedParams);
        return (ECPublicKey) keyFactory.generatePublic(pubKeySpec);
    }
}
