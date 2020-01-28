package dontUse_needsUpdate.ecdsaSignature;

import java.security.*;

public class ECDSASign {

    public static byte[] sign(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, SignatureException,
            InvalidKeyException {

        //Initialize ECDSA Signature with needsUpdate.SHA512
        //It is required to use a cryptographyJava.Hash Function with Security Strength >= Security Strength of the used ECDSA epileptic Curve
        //e.g. needsUpdate.SHA512 Security Strength = 256bit paired with "brainpoolP512r1" Curve = 256bit
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

        //Initialize ECDSA Signature with needsUpdate.SHA512
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
        byte[] dataFranz = "Franz jagt im komplett verwahrlosten Taxi quer durch Bayern.".getBytes();
        byte[] signatureFranz = sign(dataFranz, keyPair.getPrivate());

        KeyPair keyPair2 = ECDSAKeyGenerator.generateKeyPair();
        byte[] dataHallo = "hallo".getBytes();
        byte[] signatureHallo = sign(dataHallo, keyPair2.getPrivate());

        System.out.println("Signature \"signatureFranz\" was " + verify(dataFranz, signatureFranz, keyPair.getPublic()) + " for \"Franz...\" ");
        System.out.println("Signature \"signatureHallo\" was " + verify(dataFranz, signatureHallo, keyPair2.getPublic()) + " for \"Franz...\" ");
        System.out.println("Signature \"signatureHallo\" was " + verify(dataHallo, signatureHallo, keyPair2.getPublic()) + " for \"hallo\" ");
    }

}
