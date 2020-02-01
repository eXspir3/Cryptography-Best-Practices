package cryptographyJava.SymmetricEncryption;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * ChaCha20-Poly1305 is a State of the Art Algorithm for symmetric Encryption.
 * <p>
 * It uses the ChaCha20 stream cipher as well as the Poly1305 authenticator in "combined mode",
 * which provides Authenticated Encryption with Associated Data (AEAD)
 * <p>
 * !!!Important for implementation:!!!
 * use a new SECURELY RANDOM nonce of exactly 12 Bytes length for each message encrypted
 * Generation such a random nonce can be done e.g. by encrypting a counter with a secure encryption method (e.g. AES-256)
 */
public class ChaCha20Poly1305SymmetricEncryption {

    public static final String ALGORITHM = "ChaCha20-Poly1305/None/NoPadding";
    public static String KEYGENERATION_ALGORITHM = "ChaCha20";

    /**
     * Encrypt a Data Byte-Array using ChaCha20-Poly1305 AEAD
     * <p>
     * !!!Important for implementation:!!!
     * use a new SECURELY RANDOM nonce of exactly 12 Bytes length for each message encrypted
     * Generation such a random nonce can be done e.g. by encrypting a counter with a secure encryption method (e.g. AES-256)
     *
     * @param data       The encrypted Byet-Array to be encrypted
     * @param key        The ChaCha20-Poly1305 SecretKey for Encryption
     * @param nonceBytes RANDOM !! 12 Byte Nonce-Array used in the process of Encryption
     * @return Decrypted Data Byte-Array
     */
    public static byte[] encrypt(byte[] data, SecretKey key, byte[] nonceBytes) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        if (nonceBytes.length != 12) throw new IllegalBlockSizeException("Nonce must be 12 Bytes!");

        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance(ALGORITHM);

        // Create IvParamterSpec
        AlgorithmParameterSpec ivParameterSpec = new IvParameterSpec(nonceBytes);

        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), KEYGENERATION_ALGORITHM);

        // Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);

        // Perform Encryption
        return cipher.doFinal(data);
    }

    /**
     * Decrypt a Data Byte-Array using ChaCha20-Poly1305 AEAD
     * <p>
     * !!!Important for implementation:!!!
     * use a new SECURELY RANDOM nonce of exactly 12 Bytes length for each message encrypted
     * Generation such a random nonce can be done e.g. by encrypting a counter with a secure encryption method (e.g. AES-256)
     *
     * @param cipherText The encrypted Byet-Array to be decrypted
     * @param key        The ChaCha20-Poly1305 SecretKey for Decryption
     * @param nonceBytes RANDOM !! 12 Byte Nonce-Array used in the process of Encryption
     * @return Decrypted Data Byte-Array
     */
    public static byte[] decrypt(byte[] cipherText, SecretKey key, byte[] nonceBytes) throws NoSuchPaddingException, NoSuchAlgorithmException,
            IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException {
        if (nonceBytes.length != 12) throw new IllegalBlockSizeException("Nonce must be 12 Bytes!");

        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance(ALGORITHM);

        // Create IvParamterSpec
        AlgorithmParameterSpec ivParameterSpec = new IvParameterSpec(nonceBytes);

        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), KEYGENERATION_ALGORITHM);

        // Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);

        // Perform Decryption
        return cipher.doFinal(cipherText);
    }

    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEYGENERATION_ALGORITHM);
        //KeySize MUST be 256 bit - as of Java11 only 256Bit is supported
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }
}
