package cryptographyJava.CryptoHelper;

import java.security.SecureRandom;

public class CryptoUtil {
    /**
     * Generates Bytes using the secureRandom Function with specified length
     *
     * @param length Length in Bytes
     * @return Byte Array of Random Bytes
     */
    public static byte[] generateSecureRandom(int length) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] secureRandomBytes = new byte[length];
        secureRandom.nextBytes(secureRandomBytes);
        return secureRandomBytes;
    }
}
