package com.mycompany.simplesymmetricexample;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.mycompany.basersaexample.Utils;


public class OperationModes {   
    public static void main(String[]    args)
        throws Exception
    {
         
        // Texto a cifrar 32 bytes/256 bits (dos bloques de AES)
        byte[]        input = new byte[] { 
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
                (byte)0x88, (byte)0x00, (byte)0x11, (byte)0x22,
                (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66,
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
                (byte)0x88, (byte)0x00, (byte)0x11, (byte)0x22,
                (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66 };

        // Clave de 192 bits
        byte[]        keyBytes = new byte[] { 
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };

        // Modo de operacion
        String mode = "ECB"; // Intercambiar entre ECB, CBC, PCBC, CFB, CFB8, CFB32 OFB, OFB8, OFB32, CTR
        
        // Especificaciones de la clave
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        
        // Si no es modo ECB tendra IV, si es modo ECB no tendra efecto
        IvParameterSpec ivSpec = null;

        // Creamos el cifrado dependiendo del modo indicado
        Cipher cipher = Cipher.getInstance("AES/" + mode + "/NoPadding");

        // Si no es modo ECB, creamos el IV y su especificacion
        if(!mode.equals("ECB")) {
            byte[] IV = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(IV);
            ivSpec = new IvParameterSpec(IV);
        }


        System.out.println("input text : " + Utils.toHex(input));

        // Cifrado
        byte[] cipherText = new byte[input.length];
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
        ctLength += cipher.doFinal(cipherText, ctLength);
        
        System.out.println("cipher text: " + Utils.toHex(cipherText) + " bytes: " + ctLength);
        

        // Descifrado
        byte[] plainText = new byte[ctLength];
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
        ptLength += cipher.doFinal(plainText, ptLength);
        
        System.out.println("plain text : " + Utils.toHex(plainText) + " bytes: " + ptLength);
    }
}