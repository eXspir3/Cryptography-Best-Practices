package ecdsaSignature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class ECDSAKeyGeneratorBouncyCastle {

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            NoSuchProviderException {

        //It is required to use an epileptic Curve with Security Strength <= Security Strength of the used Hashing Function
        //e.g. SHA512 Security Strength = 256bit paired with "brainpoolP512r1" Curve = 256bit
        ECGenParameterSpec ecCurve = new ECGenParameterSpec("brainpoolP512r1");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
        generator.initialize(ecCurve, SecureRandom.getInstanceStrong());
        return generator.generateKeyPair();
    }

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        KeyPair keyPair = generateKeyPair();
        System.out.println(keyPair.getPublic());
        System.out.println(keyPair.getPrivate());
    }
}
