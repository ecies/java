package ru.sovcombank.ecies;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;

public final class ECKeyPair {

    private final ECPrivateKey privateKey;
    private final ECPublicKey publicKey;

    public ECKeyPair(ECPublicKey publicKey, ECPrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public ECPublicKey getPublic() {
        return publicKey;
    }

    public ECPrivateKey getPrivate() {
        return privateKey;
    }
}
