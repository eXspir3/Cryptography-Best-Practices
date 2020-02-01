package cryptographyJava.Signature;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

/**
 * ECDSA is a secure Digital Signing Algorithm built on top of the "Discrete Logarithm Probelm"
 * <p>
 * Usage of ECDSA should be preferred over RSA-Signatures as performance is much better
 * <p>
 * For example, in the most common configuration of a seurity level of 112bits RSA requires 2048-bit versus
 * ECDSA needing 224-bit keys. In the next common level of 128Bits, RSA requires a 3072-bit key,
 * while ECDSA only 256 bits. This results in RSA´s performance to decline dramatically, whereas ECDSA is only
 * slightly affected.
 */
public class ECDSASignature {

    static final String KEYGENERATION_ALGORITHM = "EC";
    static final String SIGNATURE_ALGORITHM = "SHA512withECDSA";
    static final String ELLIPTIC_CURVE = "brainpoolP512r1";

    public static byte[] sign(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, SignatureException,
            InvalidKeyException {

        //Initialize ECDSA Signature with SHA512
        //It is required to use a cryptographyJava.Hash Function with Security Strength >= Security Strength of the used ECDSA epileptic Curve
        //e.g. needsUpdate.SHA512 Security Strength = 256bit paired with "brainpoolP512r1" Curve = 256bit
        Signature ecSignature = Signature.getInstance(SIGNATURE_ALGORITHM);

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
        Signature ecSignature = Signature.getInstance(SIGNATURE_ALGORITHM);

        //Initialize Verifing of Signature
        ecSignature.initVerify(publicKey);

        //Load Data to verify
        ecSignature.update(data);

        //Verify with given Signature
        return ecSignature.verify(signature);
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        //It is required to use an epileptic Curve with Security Strength <= Security Strength of the used Hashing Function
        //e.g. needsUpdate.SHA512 Security Strength = 256bit paired with "brainpoolP512r1" Curve = 256bit
        ECGenParameterSpec ecCurve = new ECGenParameterSpec(ELLIPTIC_CURVE);
        KeyPairGenerator generator = KeyPairGenerator.getInstance(KEYGENERATION_ALGORITHM);
        generator.initialize(ecCurve, SecureRandom.getInstanceStrong());
        return generator.generateKeyPair();
    }
}
