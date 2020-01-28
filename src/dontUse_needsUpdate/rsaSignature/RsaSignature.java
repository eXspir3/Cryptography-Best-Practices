package dontUse_needsUpdate.rsaSignature;

import dontUse_needsUpdate.rsaEncryption.RsaKeyGenerator;

import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class RsaSignature {
    public static byte[] sign(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, SignatureException,
            InvalidKeyException, InvalidAlgorithmParameterException {

        //Initialize RSA PSS with needsUpdate.SHA512
        Signature privSignature  = Signature.getInstance("RSASSA-PSS");
        privSignature.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 32, 1));

        //Initialize Signing of Data and provide Private Key
        privSignature.initSign(privateKey, SecureRandom.getInstanceStrong());

        //Load Data to sign
        privSignature.update(data);

        //Sign data and store in byte array

        return privSignature.sign();
    }

    public static boolean verify(byte[] data, byte[] signature, PublicKey publicKey) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException, InvalidAlgorithmParameterException {
        //Initialize RSA PSS with needsUpdate.SHA512
        Signature pubSignature = Signature.getInstance("RSASSA-PSS");
        pubSignature.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 32, 1));

        //Initialize Verifying of Signature and provide Public Key
        pubSignature.initVerify(publicKey);

        //Load Data to Verify the Signature on
        pubSignature.update(data);

        //Verify Signature
        return pubSignature.verify(signature);
    }

    public static void main(String args[]) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException,
            InvalidAlgorithmParameterException {
        KeyPair keyPair = RsaKeyGenerator.generateKeyPair();
        byte[] data = "hallo".getBytes();
        byte[] signature = sign(data, keyPair.getPrivate());

        KeyPair keyPair2 = RsaKeyGenerator.generateKeyPair();
        byte[] data2 = "hallo2".getBytes();
        byte[] signature2 = sign(data2, keyPair2.getPrivate());

        System.out.println("Signature \"signature\" was " + verify(data, signature, keyPair.getPublic()) + " for \"data\" ");
        System.out.println("Signature \"signature2\" was " + verify(data, signature2, keyPair2.getPublic()) + " for \"data\" ");
        System.out.println("Signature \"signature2\" was " + verify(data2, signature2, keyPair2.getPublic()) + " for \"data2\" ");
    }
}
