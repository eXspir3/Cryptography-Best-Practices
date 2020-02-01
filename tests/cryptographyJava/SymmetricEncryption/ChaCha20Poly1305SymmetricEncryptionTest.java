package cryptographyJava.SymmetricEncryption;

import cryptographyJava.CryptoHelper.CryptoUtil;
import org.junit.jupiter.api.Test;
import org.opentest4j.AssertionFailedError;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Testclass for ChaCha20Poly1305SymmetricEncryption
 */
class ChaCha20Poly1305SymmetricEncryptionTest {

    /**
     * Example Plaintext
     */
    static final String PLAIN_TEXT = "Test";

    /**
     * Tests the AEAD symmetric encryption with ChaCha20-Poly1305 provided by ChaCha20Poly1305SymmetricEncryption
     */
    @Test
    void testChaCha20Poly1305SymmetricEncryption(){
        System.out.println("--------- ChaCha20-Poly1305 Symmetric Encryption ---------");

        try{
            //Generate ChaCha20 Key for use in ChaCha20-Poly1305
            SecretKey chaCha20Key = ChaCha20Poly1305SymmetricEncryption.generateKey();

            //Generate 12 nonceBytes for ChaCha20-Poly1305 using SecureRandom from CryptoHelper.CryptoUtil
            byte[] nonceBytes = CryptoUtil.generateSecureRandom(12);

            //Encrypt PlainText
            byte[] cipherTextBytes = ChaCha20Poly1305SymmetricEncryption.encrypt(PLAIN_TEXT.getBytes(), chaCha20Key, nonceBytes);
            String cipherTextString = Base64.getEncoder().encodeToString(cipherTextBytes);

            //Decrypt CipherText
            byte[] decryptedBytes = ChaCha20Poly1305SymmetricEncryption.decrypt(cipherTextBytes, chaCha20Key, nonceBytes);
            String decryptedString = new String(decryptedBytes);

            System.out.println("ChaCha20 SecretKey: \t\t" + Base64.getEncoder().encodeToString(chaCha20Key.getEncoded()));
            System.out.println("PlainText: \t\t\t\t\t" + PLAIN_TEXT);
            System.out.println("CipherText: \t\t\t\t" + cipherTextString);
            System.out.println("Decrypted CipherText: \t\t" + decryptedString);

            assertEquals(PLAIN_TEXT, decryptedString);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            System.out.println(e.getMessage());
            throw new AssertionFailedError("Something went wrong!");
        }
    }
}