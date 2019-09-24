package SHA256;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class sha256 {
    public static String getSHA256(String unhashed) throws NoSuchAlgorithmException{

        //Static Instance for SHA256 Hashing
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

        //digest () calculates SHA-256 Hash from unhashed
        byte[] digestedMessage = messageDigest.digest(unhashed.getBytes());

        // Gets the Sign Representation of the digestedMessage
        BigInteger sign = new BigInteger(1, digestedMessage);

        // Convert digestedMessage (sign Representation) to Hex Value Representation
        String hash = sign.toString(16);

        // Add Leading 0 Padding
        while(hash.length() < 32){
            hash = "0" + hash;
        }
        return hash;
    }

    //Main for Testing Purpose
    public static void main(String[] args){
        System.out.println("SHA256 Hash for \"testtest\": ");
    try{
        System.out.println(getSHA256("testtest"));
    } catch(NoSuchAlgorithmException e) {
        System.out.println(e.getMessage());
    }
    }
}
