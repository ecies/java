package ru.sovcombank.ecies;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class EciesImplTest {

    private static final String MESSAGE = "Helloworld_Helloworld_Helloworld_Helloworld_Helloworld";
    private static final String PUBHEX = "048e41409f2e109f2d704f0afd15d1ab53935fd443729913a7e8536b4cef8cf5773d4db7bbd99e9ed64595e24a251c9836f35d4c9842132443c17f6d501b3410d2";
    private static final String PRVHEX = "5b5b1a0ff51e4350badd6f58d9e6fa6f57fbdbde6079d12901770dda3b803081";
    private static final String CIPHERED = "0461816d8af10ee7af63b396c3a17dc903e6841cf7755daeabca064d13ec519f01ff0993bf30745687160b65ed684cdf8974481303537656ce6e6157accf04e22ce088e5bf55dd0ad13b4735db31d15e51c3b6257b2447fcc8cb2c55834c32bd7e0090f47b870b6c64382fa7c8466b2fb47712a258e463534c10b43d7b10bdb32e7dd46e6dc5de1cf1bf96d882cc4dde51e4cc45400eca";

    Ecies ecies = new EciesImpl();

    @Test
    public void hexEncryptDecryptTest() {
        ECKeyPair ecKeyPair = ecies.generateEphemeralKey();
        String encrypted = ecies.hexEncrypt(MESSAGE, Hex.toHexString(ecKeyPair.getPublic().getQ().getEncoded(true)));
        String decrypted = ecies.hexDecrypt(encrypted, Hex.toHexString(ecKeyPair.getPrivate().getD().toByteArray()));
        assertEquals(MESSAGE, decrypted);
    }

    @Test
    public void hexEncryptTest() {
        String s = ecies.hexEncrypt(MESSAGE, "0398afe4f150642cd05cc9d2fa36458ce0a58567daeaf5fde7333ba9b403011140");
    }

    @Test
    public void hexDecryptTest() {
        String message = ecies.hexDecrypt("04f8981a13f7be450103ccff7054688aea90778b0032f86b0f8da9593d01c08956870c190ffc26bc903c6dcc1ee5f314596160b0238c1220ec5624fc2c0ecd34802f2570723069d4047c421c24d475a81dc18239415299fe37c27428eb8de46dd97d4a3e3541a752adf513", "95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d");
//        String message = ecies.hexDecrypt(CIPHERED, PRVHEX);
        assertEquals(MESSAGE, message);
    }
}