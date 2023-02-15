/*        
 * Extraído de D. Hook, “Beginning Cryptography with Java" y adaptado
 */

package com.mycompany.tamperedexample;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import com.mycompany.basersaexample.Utils;

/**
 * Tampered message, plain encryption, AES in CTR mode
 */
public class TamperedExample
{   
    // Aquí tenemos un ejemplo de control de manipulación de un mensaje:
    //-Cifrado
    //-Manipulación (por atacante)
    //-Descifrado

    public static void main(
        String[]    args)
        throws Exception
    {
        SecureRandom	random = new SecureRandom();
        IvParameterSpec ivSpec = Utils.createCtrIvForAES(1, random);
        Key             key = Utils.createKeyForAES(256, random);
        Cipher          cipher = Cipher.getInstance("AES/CTR/NoPadding");
        String          input = "Transfer 0000100 to AC 1234-5678";

        System.out.println("input : " + input);
        
        // encryption step
        // Aquí diframos el mensaje: "Transfer 0000100 to AC 1234-5678"
        // En el modo CTR
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        
        byte[] cipherText = cipher.doFinal(Utils.toByteArray(input));

        // tampering step
        // Aquí manipulamos el mensaje
        // Sabemos la estructura del mensaje: el byte 9  es el digito inicial 
        // de la cantidad a transferir. Sabemos que  está a cero lo podemos poner 
        // a nueve:
        // cipherText[9] ^= '0' ^ '9': cuando se descifre el mensaje, el ‘0’ 
        // que debería dar en esa posición se combina con '0' ^ '9‘  quedando 
        // un 9 en esa posición. Recordar que A xor A= 0, y el operador  
        // “^=“ es “xor" sobre los bits y asignación.
        
        cipherText[9] ^= '0' ^ '9';
        
        // decryption step
        
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        
        byte[] plainText = cipher.doFinal(cipherText);
        
        // Obviamente se puede hacer por el modo de operación utilizado CTR.
        // Así se recibe: Transfer 9000100 to AC 1234-5678 en vez de
        // Transfer 0000100 to AC 1234-5678.
        System.out.println("plain : " + Utils.toString(plainText));
    }
}
