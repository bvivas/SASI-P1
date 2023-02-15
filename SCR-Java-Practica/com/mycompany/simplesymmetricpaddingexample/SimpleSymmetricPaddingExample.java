/*        
  * Extraído de D. Hook, “Beginning Cryptography with Java" y adaptado
 */
package com.mycompany.simplesymmetricpaddingexample;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import com.mycompany.basersaexample.Utils;

public class SimpleSymmetricPaddingExample
{   
    public static void main( String[]   args)
        throws Exception
    {
        // Texto a cifrar 24 bytes/192 bits (un bloque y medio de AES, se necesita padding!!!)
        byte[]        input = new byte[] { 
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
        // Clave de 192 bits
        byte[]        keyBytes = new byte[] { 
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
        
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        
        // Si necesita utilizar padding, podemos utilizar el estandard: PKCS5
        // https://en.wikipedia.org/wiki/PKCS
        // Supongamos un bloque de datos donde el último bloque de entrada es 
        // 3 bytes más corto que el tamaño de bloque del cifrado que está utilizando, 
        // entonces se agregan 3 bytes de valor 3 a los datos antes de cifrarlo.

        Cipher        cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        

        System.out.println("input : " + Utils.toHex(input));
        
        // encryption pass
        
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];

        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
        
        ctLength += cipher.doFinal(cipherText, ctLength);
        
        System.out.println("cipher: " + Utils.toHex(cipherText) + " bytes: " + ctLength);
        
        // decryption pass
        
        cipher.init(Cipher.DECRYPT_MODE, key);
        
        byte[] plainText = new byte[cipher.getOutputSize(ctLength)];

        int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
        
        ptLength += cipher.doFinal(plainText, ptLength);
        
        System.out.println("plain : " + Utils.toHex(plainText) + " bytes: " + ptLength);
    }
}
