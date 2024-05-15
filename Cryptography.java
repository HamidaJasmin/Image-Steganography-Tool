/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package w1679752.fyp.imagesteganography;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.KeyGenerator;

/**
 *
 * @author hamida
 */
public class Cryptography {

    
    //Generates The AES Encryption Key
    public static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        /* KeyGenerator class is used to generate secret keys and objects of this class are reusable.*/

        
        //Create A KeyGenerator Instance
        /*getInstance() method which accepts a String variable 
        representing the required key-generating algorithm and 
        returns a KeyGenerator object that generates secret keys.*/
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

        //The AES Key Size In The Number Of Bits
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    //Method To Encrypt The Hidden Text
    public static String Encrypt(String text) {

        try {
            //Generate The Encryption Key
            SecretKey key = generateSecretKey();

            //Make A Cipher Object & Initiate as an 
            //AES cipher with ECB mode of operation and PKCS5 padding scheme.
            /*This Transformation String Specifies The Encryption Algorithm
            - AES = Encryption Algorithm
            - ECB = Mode Of Operation, ECB is a basic mode where each block of plaintext is encrypted independently using the same key.
            - PKCS5Padding = Padding Scheme That Adds Padding Bytes To The Plaintext To Ensure It Is A 
            Multiple Of The Block Size Before Encryption. 
            This Ensures That All Blocks Can Be Encrypted And Decrypted Correctly.*/
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

            //Initilise Cipher Object To Encryption Mode
            cipher.init(Cipher.ENCRYPT_MODE, key);

            //Encrypt The Hidden Text & Conclude The Operation by Storing In The Byte Array
            byte[] encryptedText = cipher.doFinal(text.getBytes());

            //Put Together The Key And The Encrypted Text So It Can Be Decrypted Later
            //Create ByteBuffer Instance & Allocate Private Space 
            ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES + key.getEncoded().length 
                                                                  + encryptedText.length);

            //Writes The Length Of The Key, 
            //The Key Itself And The Text Into The Buffer
            buffer.putInt(key.getEncoded().length);
            buffer.put(key.getEncoded());
            buffer.put(encryptedText);

            //Return The Encrypted String
            return Base64.getEncoder().encodeToString(buffer.array());

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException 
                | BadPaddingException | InvalidKeyException ex) {
            Logger.getLogger(Cryptography.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;

    }

    //Method To Decrypt The Encryped Text In The Image
    public static String Decrypt(String encryptedText) {
        try {

            //Decode The String From The Base 64 
            byte[] EncryptedKeyAndText = Base64.getDecoder().decode(encryptedText);

            //Get The Encryption Key &Text
            //Create Byte Buffer Instance To Wrap Exisitng Byte Array
            ByteBuffer buffer = ByteBuffer.wrap(EncryptedKeyAndText);

            //Reads The Length Of The Key to Decode From The Buffer
            int keyLength = buffer.getInt();

            //Byte Array Varible Initalised To Store Key
            byte[] key = new byte[keyLength];

            //Reads The Key Bytes From The Buffer
            buffer.get(key);

            //Byte Array Varible Initalised To Get The Encryped Text By Extracting Whats Remaining
            byte[] encryptedTextt = new byte[buffer.remaining()];
            buffer.get(encryptedTextt);

            //Initalise SecretKeySpec Varibale
            //&Convert From Byte Array Using AES
            SecretKeySpec sKeySpec = new SecretKeySpec(key, "AES");

            //Make A Cipher Object & Initiate as an 
            //AES cipher with ECB mode of operation and PKCS5 padding scheme.
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

            //Initilise Cipher Object To Decryption Mode
            cipher.init(Cipher.DECRYPT_MODE, sKeySpec);

            //Decrypt The Hidden Text & Conclude The Operation by Storing In The
            //Byte Array
            byte[] decryptedText = cipher.doFinal(encryptedTextt);

            //Return The Hidden Text As A String
            return new String(decryptedText);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException 
                | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(Cryptography.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;

    }

//Method That Hashes The Password Using The Sha-256 Algorithm
    public static String hashPassword(String password) throws NoSuchAlgorithmException {
        try {
            //Create MessageDigest Instance For The SHA-256 Algorithm, 512 is stronger
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

            //Add Password Bytes To Digest
            messageDigest.update(password.getBytes(StandardCharsets.UTF_8));

            //Get The Bytes For The Hash
            byte[] hashBytes = messageDigest.digest();

            //Create a StringBuilder Object for the Hashed Password
            StringBuilder hashedPassword = new StringBuilder();

            //Convert Byte Array to Hex value
            for (byte b : hashBytes) {
                //"%02x" to print two places (02) of HexaDecimal (x)
                hashedPassword.append(String.format("%02x", b));
            }

            //Return The Hashed Password Value
            return hashedPassword.toString();

        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Cryptography.class.getName()).log(Level.SEVERE, null, ex);

        }
        return null;

    }

}
