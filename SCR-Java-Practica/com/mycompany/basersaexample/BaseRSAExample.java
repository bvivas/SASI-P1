/*        
 * Extraído de D. Hook, “Beginning Cryptography with Java" y adaptado
 */

package com.mycompany.basersaexample;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;


/**
 * Basic RSA example.
 */
public class BaseRSAExample
{
    public static void main(
        String[]    args)
        throws Exception
    {
        byte[]           input = new byte[] { (byte)0xbe, (byte)0xef };
        Cipher	         cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        KeyFactory       keyFactory = KeyFactory.getInstance("RSA");
        
                
        // Creando un objeto generador de KeyPair para RSA
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");

        // Inicializar el generador de pares de claves
        keyPairGen.initialize(2048); // mínimo 512 bits

        // Generar el par de claves
        KeyPair pair = keyPairGen.generateKeyPair();
        
        // Obtener la clave pública del par de claves
        PublicKey pubKey = pair.getPublic();  
        
        // Obtener la clave privada del par de claves
        PrivateKey privKey = pair.getPrivate();
        
        System.out.println("input : " + Utils.toHex(input));
        
        // Inicializando un objeto Cipher para cifrado o descifrado
        // Orden priv->pub
        // cipher.init(Cipher.ENCRYPT_MODE, privKey);
        // Orden pub->priv
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        
        byte[] cipherText = cipher.doFinal(input);

        System.out.println("cipher: " + Utils.toHex(cipherText));
                
        // Inicializando el mismo objeto Cipher para descifrado o cifrado
        // Orden priv->pub
        // cipher.init(Cipher.DECRYPT_MODE, pubKey);
        // Orden pub->priv
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        
        byte[] plainText = cipher.doFinal(cipherText);
        
        System.out.println("plain : " + Utils.toHex(plainText));
        
        
    }
}
