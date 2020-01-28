package dontUse_needsUpdate.rsaSignature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import dontUse_needsUpdate.rsaEncryption.RsaKeyGeneratorBouncyCastle;

import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class RsaSignatureBouncyCastle {
    public static byte[] sign(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, SignatureException,
            InvalidKeyException, NoSuchProviderException, InvalidAlgorithmParameterException {
        //Initialize RSA PSS with needsUpdate.SHA512
        Signature privSignature  = Signature.getInstance("SHA512withRSA/PSS", "BC");
        privSignature.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 32, 1));

        //Initialize Signing of Data and provide Private Key
        privSignature.initSign(privateKey, SecureRandom.getInstanceStrong());

        //Load Data to sign
        privSignature.update(data);

        //Sign data and store in byte array
        byte[] signature = privSignature.sign();
        return signature;
    }

    public static boolean verify(byte[] data, byte[] signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException, InvalidAlgorithmParameterException {
        //Initialize RSA PSS with needsUpdate.SHA512
        Signature pubSignature = Signature.getInstance("SHA512withRSA/PSS", "BC");
        pubSignature.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 32, 1));

        //Initialize Verifying of Signature and provide Public Key
        pubSignature.initVerify(publicKey);

        //Load Data to Verify the Signature on
        pubSignature.update(data);

        //Verify Signature
        return pubSignature.verify(signature);
    }

    public static void main(String args[]) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException, InvalidAlgorithmParameterException {
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("BouncyCastle - Security Provider added.");

        KeyPair keyPair = RsaKeyGeneratorBouncyCastle.generateKeyPair();
        byte[] data = "hallo".getBytes();
        byte[] signature = sign(data, keyPair.getPrivate());

        KeyPair keyPair2 = RsaKeyGeneratorBouncyCastle.generateKeyPair();
        byte[] data2 = "hallo2".getBytes();
        byte[] signature2 = sign(data2, keyPair2.getPrivate());

        System.out.println("Signature \"signature\" was " + verify(data, signature, keyPair.getPublic()) + " for \"data\" ");
        System.out.println("Signature \"signature2\" was " + verify(data, signature2, keyPair2.getPublic()) + " for \"data\" ");
        System.out.println("Signature \"signature2\" was " + verify(data2, signature2, keyPair2.getPublic()) + " for \"data2\" ");
    }

}
