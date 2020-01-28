package dontUse_needsUpdate.dsaSignature;

import java.security.*;

public class DSASign {

    public static byte[] sign(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, SignatureException,
            InvalidKeyException {

        //Initialize DSA Signature with needsUpdate.SHA512
        Signature dsaSignature = Signature.getInstance("SHA256withDSA");

        //Load privateKey
        dsaSignature.initSign(privateKey);

        //Load Data to sign
        dsaSignature.update(data);

        //Sign the Data
        return dsaSignature.sign();
    }

    public static boolean verify(byte[] data, byte[] signature, PublicKey publicKey) throws NoSuchAlgorithmException, SignatureException,
            InvalidKeyException {

        //Initialize DSA Signature with needsUpdate.SHA256
        Signature dsaSignature = Signature.getInstance("SHA256withDSA");

        //Initialize Verifing of Signature
        dsaSignature.initVerify(publicKey);

        //Load Data to verify
        dsaSignature.update(data);

        //Verify with given Signature
        return dsaSignature.verify(signature);
    }

    public static void main(String[] args) throws GeneralSecurityException {
        KeyPair keyPair = DSAKeyGenerator.generateKeyPair();
        byte[] dataFranz = "Franz jagt im komplett verwahrlosten Taxi quer durch Bayern.".getBytes();
        byte[] signatureFranz = sign(dataFranz, keyPair.getPrivate());

        KeyPair keyPair2 = DSAKeyGenerator.generateKeyPair();
        byte[] dataHallo = "hallo".getBytes();
        byte[] signatureHallo = sign(dataHallo, keyPair2.getPrivate());

        System.out.println("Signature \"signatureFranz\" was " + verify(dataFranz, signatureFranz, keyPair.getPublic()) + " for \"Franz...\" ");
        System.out.println("Signature \"signatureHallo\" was " + verify(dataFranz, signatureHallo, keyPair2.getPublic()) + " for \"Franz...\" ");
        System.out.println("Signature \"signatureHallo\" was " + verify(dataHallo, signatureHallo, keyPair2.getPublic()) + " for \"hallo\" ");
    }

}
