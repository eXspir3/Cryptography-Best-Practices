package dontUse_needsUpdate.dsaSignature;


import java.security.*;

public class DSAKeyGenerator {
    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA", "SUN");
        generator.initialize(3072);
        return generator.generateKeyPair();
    }

    public static void main(String[] args) throws GeneralSecurityException {
        KeyPair keyPair = generateKeyPair();
        System.out.println(keyPair.getPublic());
        System.out.println(keyPair.getPrivate());
    }
}
