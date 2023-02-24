package com.protocols.signatureprotocol;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.MessageDigest;

import javax.crypto.Cipher;

import com.mycompany.basersaexample.Utils;

/*
 * Basic example of a signature protocol
 * 
 * Process:
 * Digest is obtain from plain text message.
 * Digest is encrypted with private key.
 * Encrypted digest is sent with message.
 * 
 * Whoever receives the message can decrypt the digest with the public key.
 * If decrypted digest is equal to the digest produced from the plain text message,
 * the identity of the signatory can be validated.
 */
public class SignatureProtocol {
    public static void main(
        String[]    args)
        throws Exception
    {
        String           input = "This is a test to try out the signature protocol.";
        Cipher	         cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        MessageDigest    hash = MessageDigest.getInstance("SHA3-256");
        
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
        
        // Mostrar mensaje sin cifrar
        System.out.println("\nInitial message: " + input);
        
        // --------------------------------- OBTENCIÓN DEL MENSAJE ---------------------------------
        // Actualizando hash para que produzca el digest del mensaje en texto plano
        hash.update(Utils.toByteArray(input));

        // Obteniendo digest
        byte[] digest = hash.digest();

        // Mostrando digest
        System.out.println("\nInitial message digest: " + Utils.toHex(digest));

        // Inicializando un objeto Cipher para cifrado
        // Se va a encriptar el digest con la clave privada
        cipher.init(Cipher.ENCRYPT_MODE, privKey);
        
        // Se cifra el digest
        byte[] cipherDigest = cipher.doFinal(digest);

        // Se muestra el digest cifrado
        System.out.println("\nEncrypted digest: " + Utils.toHex(cipherDigest));

        // --------------------------------- LECTURA DEL MENSAJE ---------------------------------
        // Inicializando el mismo objeto Cipher para descifrado
        // Se va a descrifrar el digest con la clave pública
        cipher.init(Cipher.DECRYPT_MODE, pubKey);
        
        // Descrifrando digest
        byte[] decryptedDigest = cipher.doFinal(cipherDigest);
        
        // Mostrando digest descifrado
        System.out.println("\nDecrypted digest: " + Utils.toHex(decryptedDigest));

        // Se obtiene el digest del mensaje recibido
        hash.update(Utils.toByteArray(input));
        byte[] receivedDigest = hash.digest();

        // Se muestra el digest producido
        System.out.println("\nReceived message digest: " + Utils.toHex(receivedDigest));

        if (Utils.toHex(decryptedDigest).equals(Utils.toHex(receivedDigest))) {
            System.out.println("\nDigests are equal, which means that the identity of the sender can be confirmed and the message has not been modified.");
        } else {
            System.out.println("\nDigests are not equal, which means that someone else signed the message or the message was modified.");
        }
    }
}
