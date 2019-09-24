package ecdsaSignature;

import java.security.*;

public class ECDSASign {

    public static byte[] sign(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, SignatureException,
            InvalidKeyException {

        //Initialize ECDSA Signature with SHA512
        //It is required to use a Hash Function with Security Strength >= Security Strength of the used ECDSA epileptic Curve
        //e.g. SHA512 Security Strength = 256bit paired with "brainpoolP512r1" Curve = 256bit
        Signature ecSignature = Signature.getInstance("SHA512withECDSA");

        //Load privateKey
        ecSignature.initSign(privateKey);

        //Load Data to sign
        ecSignature.update(data);

        //Sign the Data
        return ecSignature.sign();
    }

    public static boolean verify(byte[] data, byte[] signature, PublicKey publicKey) throws NoSuchAlgorithmException, SignatureException,
            InvalidKeyException {

        //Initialize ECDSA Signature with SHA512
        Signature ecSignature = Signature.getInstance("SHA512withECDSA");

        //Initialize Verifing of Signature
        ecSignature.initVerify(publicKey);

        //Load Data to verify
        ecSignature.update(data);

        //Verify with given Signature
        return ecSignature.verify(signature);
    }

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        KeyPair keyPair = ECDSAKeyGenerator.generateKeyPair();
        byte[] data = "hallo".getBytes();
        byte[] signature = sign(data, keyPair.getPrivate());

        KeyPair keyPair2 = ECDSAKeyGenerator.generateKeyPair();
        byte[] data2 = "hallo2".getBytes();
        byte[] signature2 = sign(data2, keyPair2.getPrivate());

        System.out.println("Signature \"signature\" was " + verify(data, signature, keyPair.getPublic()) + " for \"data\" ");
        System.out.println("Signature \"signature2\" was " + verify(data, signature2, keyPair2.getPublic()) + " for \"data\" ");
        System.out.println("Signature \"signature2\" was " + verify(data2, signature2, keyPair2.getPublic()) + " for \"data2\" ");
    }

}
