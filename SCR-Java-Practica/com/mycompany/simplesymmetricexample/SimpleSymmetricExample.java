/*        
 * Extraído de D. Hook, “Beginning Cryptography with Java" y adaptado
*/
package com.mycompany.simplesymmetricexample;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import com.mycompany.basersaexample.Utils;;


/**
 * Basic symmetric encryption example
 */
public class SimpleSymmetricExample
{   
    public static void main(String[]    args)
        throws Exception
    {
         
        // Texto a cifrar 16 bytes/128 bits (un bloque de AES)
        byte[]        input = new byte[] { 
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
                (byte)0x88, (byte)0x99, (byte)0xaa, (byte)0xbb,
                (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff };
        // Clave de 192 bits
        byte[]        keyBytes = new byte[] { 
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
        
        // La clase SecretKeySpec acondiciona una clave al tipo 
        // de cifrado (en este caso al AES)
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        
        // Instanciamos la clase cipher utilizando un algoritmo 
        // concreto dado por el proveedor BC.
        Cipher        cipher = Cipher.getInstance("AES/ECB/NoPadding");
        

        System.out.println("input text : " + Utils.toHex(input));
        
        // encryption pass
        
        byte[] cipherText = new byte[input.length];
        
        // Inicializamos el cifrador en modo cifrado y con la clave.
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // Una vez que el objeto cipher está configurado para el cifrado 
        // se le pasan los datos utilizando el método cipher.update().
        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
        
        ctLength += cipher.doFinal(cipherText, ctLength);
        
        System.out.println("cipher text: " + Utils.toHex(cipherText) + " bytes: " + ctLength);
        
        // decryption pass
        
        byte[] plainText = new byte[ctLength];
        
        // Inicializamos el cifrador en modo descifrado y con la clave.
        cipher.init(Cipher.DECRYPT_MODE, key);

        int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
        
        ptLength += cipher.doFinal(plainText, ptLength);
        
        System.out.println("plain text : " + Utils.toHex(plainText) + " bytes: " + ptLength);
    }
}