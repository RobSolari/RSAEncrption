package com.rob.rsaencryption;

import java.security.KeyFactory;
import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;


/**
 *
 * @author rober
 */
public class RSAEncryption {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    //Saved private and public keys for use later on
    private static final String PRIVATE_KEY_STRING = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJhBgzcXBm5A0srvFFu4FsBy+LLW+X0sH/9RvP40VIGOCusY0/CqA65YXWqyQE5jQCegBmnAeVYSvK+3PU4Y1fmr1uiquE6sZB5sl96T0ka+PKzPf4oKoAi6nwLUSenj5xTFjLsFGiuMXrCpMCPImf9JBVk89TJV43Xs3DSNKoj1AgMBAAECgYBsDysCgVv2ChnRH4eSZP/4zGCIBR0C4rs+6RM6U4eaf2ZuXqulBfUg2uRKIoKTX8ubk+6ZRZqYJSo3h9SBxgyuUrTehhOqmkMDo/oa9v7aUqAKw/uoaZKHlj+3p4L3EK0ZBpz8jjs/PXJc77Lk9ZKOUY+T0AW2Fz4syMaQOiETzQJBANF5q1lntAXN2TUWkzgir+H66HyyOpMu4meaSiktU8HWmKHa0tSB/v7LTfctnMjAbrcXywmb4ddixOgJLlAjEncCQQC6Enf3gfhEEgZTEz7WG9ev/M6hym4C+FhYKbDwk+PVLMVR7sBAtfPkiHVTVAqC082E1buZMzSKWHKAQzFL7o7zAkBye0VLOmLnnSWtXuYcktB+92qh46IhmEkCCA+py2zwDgEiy/3XSCh9Rc0ZXqNGD+0yQV2kpb3awc8NZR8bit9nAkBo4TgVnoCdfbtq4BIvBQqR++FMeJmBuxGwv+8n63QkGFQwVm6vCuAqFHBtQ5WZIGFbWk2fkKkwwaHogfcrYY/ZAkEAm5ibtJx/jZdPEF9VknswFTDJl9xjIfbwtUb6GDMc0KH7v+QTBW4GsHwt/gL+kGvLOLcEdLL5rau3IC7EQT0ZYg==";
    private static final String PUBLIC_KEY_STRING =  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYQYM3FwZuQNLK7xRbuBbAcviy1vl9LB//Ubz+NFSBjgrrGNPwqgOuWF1qskBOY0AnoAZpwHlWEryvtz1OGNX5q9boqrhOrGQebJfek9JGvjysz3+KCqAIup8C1Enp4+cUxYy7BRorjF6wqTAjyJn/SQVZPPUyVeN17Nw0jSqI9QIDAQAB";

    //Function to create the Public and Private keys
    public void init(){
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024);
            KeyPair pair = generator.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();
        } catch (Exception ignored) {
        }
    }


    //Function to get the public and private keys from the saved public and private keys above
    public void initFromStrings(){
        try{
            X509EncodedKeySpec keySpecPublic = new X509EncodedKeySpec(decode(PUBLIC_KEY_STRING));  //X509 is a standard format for public keys
            PKCS8EncodedKeySpec keySpecPrivate = new PKCS8EncodedKeySpec(decode(PRIVATE_KEY_STRING));  //PKCS8 is a standard syntax for storing private keys

            KeyFactory keyFactory = KeyFactory.getInstance("RSA"); 

            publicKey = keyFactory.generatePublic(keySpecPublic);
            privateKey = keyFactory.generatePrivate(keySpecPrivate);
        }catch (Exception ignored){}
    }

    //Function to print out both the public and private keys
    public void printKeys(){
        System.err.println("Public key\n"+ encode(publicKey.getEncoded()));
        System.err.println("Private key\n"+ encode(privateKey.getEncoded()));
    }

    //Function to encode the public key
    public String encrypt(String message) throws Exception {
        byte[] messageToBytes = message.getBytes();  //Gets the bytes from the string
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");  //Creates a new Cipher
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);        //Cipher is initialized to Encrypt with the public key
        byte[] encryptedBytes = cipher.doFinal(messageToBytes); //Encrypts the message
        return encode(encryptedBytes);  //Returns the encoded bytes
    }

    //Function to encode the data by base64 
    //Base64 encoding converts the binary data into text format, which is passed through communication channel where a user can handle text safely
    private static String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }


    //Function to decrypt the message
    public String decrypt(String encryptedMessage) throws Exception {
        byte[] encryptedBytes = decode(encryptedMessage);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);   //Cipher is initialized to Decrypt with private key
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes); //Decrypts as the final part of the function 
        return new String(decryptedMessage, "UTF8");
    }
    
    //Function to decode the data by base64 
    private static byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }


    public static void main(String[] args) {
        RSAEncryption rsaEncryption = new RSAEncryption();
        rsaEncryption.initFromStrings();
        
        try{
            Scanner reader = new Scanner(System.in);  //Scanner to get the user to input a string to encrypt and possibly be sent to someone.
            System.out.println("Enter a String to encrypt: ");
            String message = reader.nextLine(); 
            reader.close();
            String encryptedMessage = rsaEncryption.encrypt(message);//Encrypts the message
            String decryptedMessage = rsaEncryption.decrypt(encryptedMessage);//Decrypts tthe encrypted message

            System.err.println("Encrypted:\n"+encryptedMessage);//Prints out the encrypted message
            System.err.println("Decrypted:\n"+decryptedMessage); //Prints out the decrypted message
          

            rsaEncryption.printKeys();  //Prints the public and private keys
         }catch (Exception ingored){}

        

    }
}