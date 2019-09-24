package rsaEncryption;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;

public class RsaEncryptionBouncyCastle {
    public static byte[] encrypt(byte[] data, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException,
            BadPaddingException, InvalidKeyException, IllegalBlockSizeException, InvalidAlgorithmParameterException,
            NoSuchProviderException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA512AndMGF1Padding", "BC");
        OAEPParameterSpec oaepParameterSpec = new OAEPParameterSpec("SHA-512", "MGF1",
                MGF1ParameterSpec.SHA512, PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParameterSpec);
        byte[] encryptData = cipher.doFinal(data);
        return encryptData;
    }

    public static byte[] decrypt(byte[] data, PrivateKey privateKey) throws BadPaddingException, IllegalBlockSizeException,
            InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            NoSuchProviderException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA512AndMGF1Padding", "BC");
        OAEPParameterSpec oaepParameterSpec = new OAEPParameterSpec("SHA-512", "MGF1",
                MGF1ParameterSpec.SHA512, PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParameterSpec);
        byte[] decryptData = cipher.doFinal(data);
        return decryptData;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        KeyPair keyPair = RsaKeyGeneratorBouncyCastle.generateKeyPair();
        String testMessage = "hallo!";
        byte[] encryptedBytes = encrypt(testMessage.getBytes(), keyPair.getPublic());
        String decryptedMessage = new String(decrypt(encryptedBytes, keyPair.getPrivate()));
        System.out.println("testMessage: " + testMessage);
        System.out.println("encryptedBytes: " + Base64.getEncoder().encodeToString(encryptedBytes));
        System.out.println("decryptedMessage: "+ decryptedMessage);
    }
}
