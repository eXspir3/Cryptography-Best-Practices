package rsaEncryption;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class RsaKeyGenerator {

    //Generate RSA Key with size of at least 3072 bits
    //Use "SecureRandom.getInstanceStrong()" for more secure Randomness
    //For Availability Oriented Implementation use the nonBlocking "SecureRandom.getInstance()"
    //If executed on Windows Systems, it is strongly advised not to use "SecureRandom.getInstance()" as this will trigger
    //the insecure SHA1PRNG

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3072, SecureRandom.getInstanceStrong());
        return generator.generateKeyPair();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        KeyPair keyPair = generateKeyPair();
        System.out.println(keyPair.getPrivate());
        System.out.println(keyPair.getPublic());
    }
}
