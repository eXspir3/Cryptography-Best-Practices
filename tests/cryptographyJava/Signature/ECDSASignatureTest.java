package cryptographyJava.Signature;

import org.junit.jupiter.api.Test;
import org.opentest4j.AssertionFailedError;

import java.security.*;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Testclass for ECDSASignature
 */
class ECDSASignatureTest {

    /**
     * Plaintext for Data-Arrays
     */
    final static String PLAIN_TEXT_1 = "TEST-1";
    final static String PLAIN_TEXT_2 = "TEST-2";

    /**
     * Get 2 different Byte-Arrays for signing and validation
     */
    byte[] data = PLAIN_TEXT_1.getBytes();
    byte[] data2= PLAIN_TEXT_2.getBytes();

    /**
     * Test the "ECDSA Signatures from ECDSASignature.java
     */

    @Test
    void testECDSASignature(){
        System.out.println("--------- ECDSA Signing / Verification ---------");

        try{
            /*
             *Generate 2 different Keypairs for Signing / Validation
             */
            KeyPair keyPair = ECDSASignature.generateKeyPair();
            KeyPair keyPair2 = ECDSASignature.generateKeyPair();

            byte[] signatureTest1 = ECDSASignature.sign(data, keyPair.getPrivate());
            byte[] signatureTest2 = ECDSASignature.sign(data2, keyPair2.getPrivate());

            System.out.println("Text in Byte-Array 1: \t\t\t\t\t\t\t\t" + PLAIN_TEXT_1);
            System.out.println("Text in Byte-Array 2: \t\t\t\t\t\t\t\t" + PLAIN_TEXT_2);

            System.out.println("Signature of Byte-Array-1 with KeyPair 1: \t\t\t" + Base64.getEncoder().encodeToString(signatureTest1));
            System.out.println("Signature of Byte-Array-2 with KeyPair 2: \t\t\t" + Base64.getEncoder().encodeToString(signatureTest2));

            /*
             * Verify the Signatures against the Data
             */
            boolean sign1Test1Key1 = ECDSASignature.verify(data, signatureTest1, keyPair.getPublic());
            boolean sign2Test1Key2 = ECDSASignature.verify(data, signatureTest2, keyPair2.getPublic());
            boolean sign2Test2Key2 = ECDSASignature.verify(data2, signatureTest2, keyPair2.getPublic());

            System.out.println("Signature \"signatureTest1\" was " + sign1Test1Key1 + " for Data \"1\" with Signature \"1\"");
            System.out.println("Signature \"signatureTest2\" was " + sign2Test1Key2+ " for Data \"1\" with Signature \"2\"");
            System.out.println("Signature \"signatureTest2\" was " + sign2Test2Key2 + " for Data \"2\" with Signature \"2\" ");

            assertTrue(sign1Test1Key1);
            assertFalse(sign2Test1Key2);
            assertTrue(sign2Test2Key2);

        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            System.out.println(e.getMessage());
            throw new AssertionFailedError("Something went wrong");
        }

    }
}