package ecies.common;

import lombok.experimental.UtilityClass;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.util.Arrays;

@UtilityClass
public class ConvertUtils {

    public String toHexStringBytesPadded(ECPrivateKey privateKey) {
        return toHexStringBytesPadded(privateKey.getD());
    }

    public String toHexStringBytesPadded(BigInteger privateKey) {
        return toHexStringBytesPadded(privateKey.toByteArray());
    }

    public String toHexStringBytesPadded(byte[] privateKey) {
        if (privateKey[0] == 0) {
            return Hex.toHexString(Arrays.copyOfRange(privateKey, 1, privateKey.length));
        }
        return Hex.toHexString(privateKey);
    }
}
