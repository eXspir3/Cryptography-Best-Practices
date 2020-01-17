package needsUpdate.ecdsaSignature;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class ECDSAKeyGenerator {

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        //It is required to use an epileptic Curve with Security Strength <= Security Strength of the used Hashing Function
        //e.g. needsUpdate.SHA512 Security Strength = 256bit paired with "brainpoolP512r1" Curve = 256bit
        ECGenParameterSpec ecCurve = new ECGenParameterSpec("brainpoolP512r1");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(ecCurve, SecureRandom.getInstanceStrong());
        return generator.generateKeyPair();
    }

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        KeyPair keyPair = generateKeyPair();
        System.out.println(keyPair.getPublic());
        System.out.println(keyPair.getPrivate());
    }
}
