package AsymmetricEncryption;

import cryptographyJava.AsymmetricEncryption.RSAAsymmetricEncryption;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Testclass for {cryptographyJava.RSAAsymmetricEncryption}
 */
class RSAAsymmetricEncryptionTest {

    private static final String PLAIN_TEXT = "Test";

    /**
     * Tests the asymmetric Encryption Algorithm "RSA-OAEPwithSHA-512andMGF1"
     */
    @Test
    void testRSAAsymmetricEncryption() {
        System.out.println("--------- RSA-OAEPwithSHA-512andMGF1 Encryption ---------");
        System.out.println("Plain Text: \t\t\t" + PLAIN_TEXT);
        try {
            KeyPair keyPair = RSAAsymmetricEncryption.generateKeyPair();
            byte[] encryptedBytes = RSAAsymmetricEncryption.encrypt(PLAIN_TEXT.getBytes(), keyPair.getPublic());
            String decryptedPlainText = new String(RSAAsymmetricEncryption.decrypt(encryptedBytes, keyPair.getPrivate()));

            System.out.println("Encrypted Text: \t\t" + Base64.getEncoder().encodeToString(encryptedBytes));
            System.out.println("Decrypted Text: \t\t" + decryptedPlainText);

            Assertions.assertEquals(PLAIN_TEXT, decryptedPlainText);
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            System.out.println("Encryption failed: " + e.getMessage());
        }
    }

}