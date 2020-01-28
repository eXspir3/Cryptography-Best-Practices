package cryptographyJava.HashSecure;

import org.junit.jupiter.api.Test;
import java.security.NoSuchAlgorithmException;

/**
 * Testclass for Argon2iHash
 */
class Argon2iHashSecureTest {

    /**
     * Example PlainText
     */
    private static final String PLAIN_TEXT = "Test";

    /**
     * Tests the standard hashing Algorithm "Argon2i" provided by Argon2iHash
     */

    @Test
    void testArgon2iHash(){
        System.out.println("--------- Argon2i Hashing ---------");
        System.out.println("Plain Text: \t\t\t" + PLAIN_TEXT);
        String hashed;
        try{
            hashed = Argon2iHashSecure.hash(PLAIN_TEXT);
            System.out.println("Hashed Text: \t\t\t" + hashed);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Hashing failed: " + e.getMessage());
        }
    }
}