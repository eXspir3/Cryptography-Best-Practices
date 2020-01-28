package Hash;

import cryptographyJava.Hash.SHA256Hash;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

/**
 * Testclass for SHA256Hash
 */
class SHA256HashTest {

    /**
     * Example PlainText
     */
    private static final String PLAIN_TEXT = "Test";

    /**
     * Tests the standard hashing Algorithm "SHA256" provided by SHA256Hash
     */

    @Test
    void testSHA256Hash(){
        System.out.println("--------- SHA256 Hashing ---------");
        System.out.println("Plain Text: \t\t\t" + PLAIN_TEXT);
        String hashed;
        try{
            hashed = SHA256Hash.hash(PLAIN_TEXT);
            System.out.println("Hashed Text: \t\t\t" + hashed);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Hashing failed: " + e.getMessage());
        }
    }
}