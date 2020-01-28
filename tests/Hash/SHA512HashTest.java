package Hash;

import cryptographyJava.Hash.SHA512Hash;
import org.junit.jupiter.api.Test;
import java.security.NoSuchAlgorithmException;

/**
 * Testclass for SHA512Hash
 */
class SHA512HashTest {

    /**
     * Example PlainText
     */
    private static final String PLAIN_TEXT = "Test";

    /**
     * Tests the standard hashing Algorithm "SHA512" provided by SHA512Hash
     */

    @Test
    void testSHA512Hash(){
        System.out.println("--------- SHA512 Hashing ---------");
        System.out.println("Plain Text: \t\t\t" + PLAIN_TEXT);
        String hashed;
        try{
            hashed = SHA512Hash.hash(PLAIN_TEXT);
            System.out.println("Hashed Text: \t\t\t" + hashed);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Hashing failed: " + e.getMessage());
        }
    }
}