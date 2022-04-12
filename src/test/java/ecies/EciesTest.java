package ecies;

import ecies.common.ConvertUtils;
import ecies.common.ECKeyPair;
import org.apache.http.client.fluent.Form;
import org.apache.http.client.fluent.Request;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EciesTest {

    private static final String PYTHON_BACKEND_URI = "https://eciespy.herokuapp.com/";
    private static final String MESSAGE = "Helloworld_Helloworld_Helloworld_Helloworld_Helloworld";
    private static final String PRVHEX = "95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d";
    private static final String CIPHERED = "0453a537e11be4afada87c04a1651355a357fcd5ed00b0330009bcc5ebfe3194580d07d0a7054840949392f26cc2938c46dd5889bb6aee8840c560f19453ea8b39a37c3ad50bb49a55fe3b48da351ecf1c22a64a4dd891d1738f7527e341efea5a863f7b62b66b0e4bc51a141e42f4143feff81af26ee20bf0cfae556f8073d9023b94cea0fc53c93c0fc9d438c149eae1cd62306afef2";

    private static final String TESTING_PYTHON_PUBKEY_HEX = "0498afe4f150642cd05cc9d2fa36458ce0a58567daeaf5fde7333ba9b403011140a4e28911fcf83ab1f457a30b4959efc4b9306f514a4c3711a16a80e3b47eb58b";
    private static final String TESTING_PYTHON_PRIVKEY_HEX = "95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d";
    private static final String TESTING_JSON_MSG = "{\"code\":0,\"msg\":\"ok\",\"data\":{\"pageNumber\":1,\"pageSize\":10,\"total\":0,\"list\":[],\"realTotal\":0}}{\"code\":0,\"msg\":\"ok\",\"data\":{\"pageNumber\":1,\"pageSize\":10,\"total\":0,\"list\":[],\"realTotal\":0}}{\"code\":0,\"msg\":\"ok\",\"data\":{\"pageNumber\":1,\"pageSize\":10,\"total\":0,\"list\":[],\"realTotal\":0}}";

    @Test
    void encryptDecryptHexTest() {
        ECKeyPair ecKeyPair = Ecies.generateEcKeyPair();
        String encrypted = Ecies.encrypt(ecKeyPair.getPublicHex(true), MESSAGE);
        String decrypted = Ecies.decrypt(ecKeyPair.getPrivateHex(), encrypted);
        assertEquals(MESSAGE, decrypted);
    }

    @Test
    void encryptDecryptBinaryTest() {
        ECKeyPair ecKeyPair = Ecies.generateEcKeyPair();
        byte[] encrypted = Ecies.encrypt(ecKeyPair.getPublicBinary(true), MESSAGE.getBytes(StandardCharsets.UTF_8));
        String decrypted = new String(Ecies.decrypt(ecKeyPair.getPrivateBinary(), encrypted));
        assertEquals(MESSAGE, decrypted);
    }

    @Test
    void encryptDecryptPredefinedKeysTest() {
        String encrypt = Ecies.encrypt(TESTING_PYTHON_PUBKEY_HEX, TESTING_JSON_MSG);
        String decrypt = Ecies.decrypt(TESTING_PYTHON_PRIVKEY_HEX, encrypt);
        assertEquals(TESTING_JSON_MSG, decrypt);
    }

    @Test
    void encryptDecryptStabilityTest() {
        for (int i = 0; i < 100; i++) {
            encryptDecryptHexTest();
        }
    }

    @Test
    void encryptDecryptBytesTest() {
        ECKeyPair ecKeyPair = Ecies.generateEcKeyPair();
        byte[] encrypted = Ecies.encrypt(ecKeyPair.getPublic().getQ().getEncoded(true), MESSAGE.getBytes(StandardCharsets.UTF_8));
        byte[] decrypted = Ecies.decrypt(ecKeyPair.getPrivate().getD().toByteArray(), encrypted);
        assertEquals(MESSAGE, new String(decrypted, StandardCharsets.UTF_8));
    }

    @Test
    void decryptWithKnownMessageAndKeyTest() {
        String message = Ecies.decrypt(PRVHEX, CIPHERED);
        assertEquals(MESSAGE, message);
    }

    @Test
    void encryptDecryptAgainstPythonVersionTest() throws IOException {
        ECKeyPair ecKeyPair = Ecies.generateEcKeyPair();

        String cipherTextPython = Request.Post(PYTHON_BACKEND_URI).bodyForm(
                Form.form()
                        .add("data", MESSAGE)
                        .add("pub", Hex.toHexString(ecKeyPair.getPublic().getQ().getEncoded(true)))
                        .build()
        ).execute().returnContent().asString();
        byte[] decrypt = Ecies.decrypt(ecKeyPair.getPrivate().getD().toByteArray(), Hex.decode(cipherTextPython));

        assertEquals(MESSAGE, new String(decrypt, StandardCharsets.UTF_8));

        String encryptedText = Ecies.encrypt(Hex.toHexString(ecKeyPair.getPublic().getQ().getEncoded(true)), MESSAGE);
        String pythonResponse = Request.Post(PYTHON_BACKEND_URI).bodyForm(
                Form.form()
                        .add("data", encryptedText)
                        .add("prv", ConvertUtils.toHexStringBytesPadded(ecKeyPair.getPrivate()))
                        .build()
        ).execute().returnContent().asString();
        assertEquals(MESSAGE, pythonResponse);
    }

    @Test
    void encryptDecryptAgainstPythonVersionPredefinedKeysTest() throws IOException {
        String cipherTextPython = Request.Post(PYTHON_BACKEND_URI).bodyForm(
                Form.form()
                        .add("data", TESTING_JSON_MSG)
                        .add("pub", TESTING_PYTHON_PUBKEY_HEX)
                        .build()
        ).execute().returnContent().asString();
        String decrypt = Ecies.decrypt(TESTING_PYTHON_PRIVKEY_HEX, cipherTextPython);

        assertEquals(TESTING_JSON_MSG, decrypt);

        String encryptedText = Ecies.encrypt(TESTING_PYTHON_PUBKEY_HEX, TESTING_JSON_MSG);
        String pythonResponse = Request.Post(PYTHON_BACKEND_URI).bodyForm(
                Form.form()
                        .add("data", encryptedText)
                        .add("prv", TESTING_PYTHON_PRIVKEY_HEX)
                        .build()
        ).execute().returnContent().asString();
        assertEquals(TESTING_JSON_MSG, pythonResponse);
    }
}