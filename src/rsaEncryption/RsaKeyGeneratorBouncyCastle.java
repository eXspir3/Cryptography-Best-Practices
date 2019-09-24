package rsaEncryption;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;

public class RsaKeyGeneratorBouncyCastle {

    //Generate RSA Key with size of at least 3072 bits
    //Use "SecureRandom.getInstanceStrong()" for more secure Randomness
    //For Availability Oriented Implementation use the nonBlocking "SecureRandom.getInstance()"
    //If executed on Windows Systems, it is strongly advised not to use "SecureRandom.getInstance()" as this will trigger
    //the insecure SHA1PRNG

    public static KeyPair generateKeyPair() throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));
        return generator.generateKeyPair();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPair keyPair = generateKeyPair();
        System.out.println(keyPair.getPrivate());
        System.out.println(keyPair.getPublic());
    }
}
