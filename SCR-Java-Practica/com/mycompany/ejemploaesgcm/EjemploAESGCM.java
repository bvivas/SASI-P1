/*
 * Ejemplo de AES en modo GCM
 */
package com.mycompany.ejemploaesgcm;


import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.mycompany.basersaexample.Utils;


public class EjemploAESGCM {
    static String plainText = "Esto es una prueba del modo de cifrado GCM para el AES";
    public static final int AES_KEY_SIZE = 256;
    public static final int GCM_IV_LENGTH = 12;
    public static final int GCM_TAG_LENGTH = 16;
    
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
               
        // inicializo para generar la clave
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_KEY_SIZE);
        
         // genero la clave
        SecretKey key = kg.generateKey();
        byte[] IV = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(IV);

        // Salida del texto plano
        System.out.println("Texto Plano : " + plainText);
                
        // Objeto para cifrar y descifrar
        // AES-GCM es un modo de operación de cifrado de bloques 
        // que proporciona alta velocidad de cifrado autenticado 
        // e integridad de datos. En el modo GCM, el cifrado de 
        // bloque se transforma en cifrado de flujo y, por lo tanto, 
        // no se necesita "padding".
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
         // Creo las especificaciones de la la clave
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
        
        // Creo las especificaciones del modo GCM
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);
        
        
        //------------------------ Cifrar ---------------
        // Inicializo el objeto difrador en modo cifrado
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
        
        // Cifro
        byte[] cipherText = cipher.doFinal(Utils.toByteArray(plainText));
        
        // Salida del texto cifrado en hexadecimal
        System.out.println("Texto Cifrado (hexadecimal): " + Utils.toHex(cipherText));
        
        
        //------------------------ DesCifrar ---------------
        // Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
        
        // Perform Decryption
        byte[] decryptedText = cipher.doFinal(cipherText);
        
        // Salida del texto descifrado
        System.out.println("Texto Descifrado: " + Utils.toString(decryptedText));
    }       
}
    