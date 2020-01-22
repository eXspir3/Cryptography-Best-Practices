package cryptographyJava.AsymmetricEncryption;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

/**
* Comment missing - explaination why oaepsha-512mgf1 is secure
*/
public class RSAAsymmetricEncryption {

    static final String KEYGENERATION_ALGORITHM = "RSA";
    static final String CIPHER_ALGORITHM = "RSA/ECB/OAEPWithSHA-512AndMGF1Padding";
    static final String MD_ALGORITHM = "SHA-512";
    static final String MGF_ALGORITHM = "MGF1";
    static final int KEYLENGTH = 4096;

    /**
     * Secure Encryption using RSA with Optimal Asymmetric Encryption Padding (OAEP) SHA-512 and MGF1
     * RSA OAEP provides State of the Art Encryption.
     *
     * @param data      The data as ByteArray to encrypt
     * @param publicKey The RSA PublicKey from RSAKeypair that is used to encrypt
     * @return The encrypted data as ByteArray
     */
    public static byte[] encrypt(byte[] data, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        OAEPParameterSpec oaepParameterSpec = new OAEPParameterSpec(MD_ALGORITHM, MGF_ALGORITHM,
                MGF1ParameterSpec.SHA512, PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParameterSpec);
        return cipher.doFinal(data);
    }

    /**
     * Secure Decryption using RSA with Optimal Asymmetric Encryption Padding (OAEP) SHA-512 and MGF1
     * RSA OAEP provides State of the Art Encryption.
     *
     * @param data      The encrypted data to decrypt
     * @param privateKey The privateKey from the RSAKeypair
     * @return Decrypted Data as ByteArray
     */
    public static byte[] decrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        OAEPParameterSpec oaepParameterSpec = new OAEPParameterSpec(MD_ALGORITHM, MGF_ALGORITHM,
                MGF1ParameterSpec.SHA512, PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParameterSpec);
        return cipher.doFinal(data);
    }

    /**
     * Generates a generic RSA Keypair with KEYLENGTH Bits
     * @return The RSA Keypair
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEYGENERATION_ALGORITHM);
        keyPairGenerator.initialize(new RSAKeyGenParameterSpec(KEYLENGTH, RSAKeyGenParameterSpec.F4), SecureRandom.getInstanceStrong());
        return keyPairGenerator.generateKeyPair();
    }


}
