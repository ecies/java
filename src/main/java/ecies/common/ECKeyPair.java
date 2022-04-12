package ecies.common;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.util.encoders.Hex;

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

    public byte[] getPublicBinary(boolean encoded) {
        return publicKey.getQ().getEncoded(encoded);
    }

    public byte[] getPrivateBinary() {
        return privateKey.getD().toByteArray();
    }

    public String getPublicHex(boolean encoded) {
        return Hex.toHexString(getPublicBinary(encoded));
    }

    public String getPrivateHex() {
        return Hex.toHexString(getPrivateBinary());
    }
}
