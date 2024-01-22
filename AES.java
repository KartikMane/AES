/*
Possible KEY_SIZE values are 128,192 and 256
Possible T_Len values are 128,120,112,18 and 96
*/


import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AES
{
    private SecretKey key;
    private Cipher enc;
    private int KEY_SIZE=128;
    private int T_LEN=128;
    public void init() throws Exception
    {
        KeyGenerator generator;
        generator  = KeyGenerator.getInstance("AES");
        generator.init(KEY_SIZE); //Initialize the key size
        key=generator.generateKey();  //Generating a key
    }
    public String encrypt(String message) throws Exception
    {
        byte[] b=message.getBytes(); // Getting byte array
        enc = Cipher.getInstance("AES/GCM/NoPadding");
        enc.init(Cipher.ENCRYPT_MODE,key); // As we are encrypting and pass the secret key
        byte[] br=enc.doFinal(b); // THIS METHOD RETURNS A BYTE ARRAY
        return encode(br);
    }
    public String decrypt(String data) throws Exception
    {
        byte[] message = decode(data);
        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(T_LEN,enc.getIV());
        dec.init(Cipher.DECRYPT_MODE,key,spec);
        byte[] decr=dec.doFinal(message);
        return new String(decr);
    }
    private String encode(byte[] data)
    {
        return Base64.getEncoder().encodeToString(data); // Encodes a byte array to a string
    }
    private byte[] decode(String data)
    {
        return Base64.getDecoder().decode(data);
    }

    public static void main(String[] args)
    {
        try
        {
            AES a = new AES();
            a.init();
            String encryptedmsg=a.encrypt("HELLO WORLD");
            String decryptedmsg=a.decrypt(encryptedmsg);

            System.err.println("Encrypted Message :"+encryptedmsg);
            System.err.println("Decrypted Message :"+decryptedmsg);
        }
        catch (Exception e)
        {
            System.out.println(e);
        }
    }
}
