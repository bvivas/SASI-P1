package com.protocols.signatureprotocol;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

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
    // Esta clase contiene todo lo que el emisor envía al receptor
    private class SenderResponse {
        private PublicKey pubKey;
        private byte[] cipheredDigest;
        private byte[] cipheredMessage;
    }

    // Esta función devuelve el mensaje que enviaría un emisor en la conversación con RSA
    public SenderResponse sender(String inputMessage, String rsaInstance, String hashInstance, String aesInstance, Key aesKey, IvParameterSpec ivSpec)
        throws Exception
    {
        // Instanciado cifrados
        Cipher asymmetricCipher = Cipher.getInstance(rsaInstance);
        MessageDigest hash = MessageDigest.getInstance(hashInstance);
        Cipher symmetricCipher = Cipher.getInstance(aesInstance);

        // Mostrando mensaje cabecera del emisor
        System.out.println("\n---------- SENDER AREA ----------");

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
        System.out.println("\nInitial message: " + inputMessage);

        // Actualizando hash para que produzca el digest del mensaje en texto plano
        hash.update(Utils.toByteArray(inputMessage));

        // Obteniendo digest
        byte[] digest = hash.digest();

        // Mostrando digest
        System.out.println("\nInitial message digest: " + Utils.toHex(digest));

        // Cifrando el digest con la clave privada
        asymmetricCipher.init(Cipher.ENCRYPT_MODE, privKey);
        byte[] cipherDigest = asymmetricCipher.doFinal(digest);

        // Se muestra el digest cifrado
        System.out.println("\nEncrypted digest: " + Utils.toHex(cipherDigest));

        // Cifrando el mensaje con la clave simétrica
        symmetricCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        byte[] cipheredMessage = symmetricCipher.doFinal(Utils.toByteArray(inputMessage));

        // Se muestra el mensaje cifrado
        System.out.println("\nEncrypted message: " + Utils.toHex(cipheredMessage));

        // Definiendo el mensaje del emisor
        SenderResponse response = new SenderResponse();
        response.pubKey = pubKey;
        response.cipheredDigest = cipherDigest;
        response.cipheredMessage = cipheredMessage;

        // Devolviendo mensaje
        return response;
    }

    // Esta función simula a un intruso que intercepta y modifica el mensaje encriptado
    public SenderResponse intruder(SenderResponse senderMessage) 
    throws Exception
    {
        // Mostrando mensaje cabecera del intruso
        System.out.println("\n---------- INTRUDER AREA ----------");

        // Devolviendo el mensaje modificado
        return senderMessage;
    }

    // Esta función comprueba el mensaje enviado por el emisor para ver que es correcto y la firma auténtica
    public void receiver(SenderResponse senderMessage, String rsaInstance, String hashInstance, String aesInstance, Key aesKey, IvParameterSpec ivSpec)
        throws Exception
    {
        // Instanciando cifrados
        Cipher asymmetricCipher = Cipher.getInstance(rsaInstance);
        MessageDigest hash = MessageDigest.getInstance(hashInstance);
        Cipher symmetricCipher = Cipher.getInstance(aesInstance);

        // Mostrando mensaje cabecera del receptor
        System.out.println("\n---------- RECEIVER AREA ----------");

        // Descifrando el digest con la clave pública
        asymmetricCipher.init(Cipher.DECRYPT_MODE, senderMessage.pubKey);
        byte[] decryptedDigest = asymmetricCipher.doFinal(senderMessage.cipheredDigest);
        
        // Mostrando digest descifrado
        System.out.println("\nDecrypted digest: " + Utils.toHex(decryptedDigest));

        // Descrifrando mensaje recibido con la clave simétrica
        symmetricCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        byte[] decryptedMessage = symmetricCipher.doFinal(senderMessage.cipheredMessage);

        // Mostrando mensaje descifrado
        System.out.println("\nDecrypted message: " + Utils.toHex(decryptedMessage));

        // Se obtiene el digest del mensaje descifrado
        hash.update(decryptedMessage);
        byte[] receivedDigest = hash.digest();
        
        // Se muestra el digest producido
        System.out.println("\nDecrypted message's digest: " + Utils.toHex(receivedDigest));
        
        // Comparando digests para comprobar la autenticidad de la firma y la integridad del mensaje
        if (Utils.toHex(decryptedDigest).equals(Utils.toHex(receivedDigest))) {
            System.out.println("\nDigests are equal, which means that the identity of the sender can be confirmed and the message has not been modified.");
        } else {
            System.out.println("\nDigests are not equal, which means that someone else signed the message or the message was modified.");
        }
    }

    // Función principal
    public static void main(
        String[]    args)
        throws Exception
    {
        // Definiendo variables necesarias
        Boolean tamperedMessage = true; // Defines if the message will be intercepted and tampered or not
        String input = "Transfer 0000100 to AC 1234-5678";
        String rsaInstance = "RSA/ECB/PKCS1Padding";
        String hashInstance = "SHA3-256";
        String aesInstance = "AES/CTR/NoPadding";
        SignatureProtocol protocol = new SignatureProtocol();
        SecureRandom random = new SecureRandom();
        IvParameterSpec ivSpec = Utils.createCtrIvForAES(1, random);
        Key aesKey = Utils.createKeyForAES(256, random);
        
        // Obteniendo mensaje del emisor
        SenderResponse senderMessage = protocol.sender(input, rsaInstance, hashInstance, aesInstance, aesKey, ivSpec);

        // Interceptando y modificando el mensaje encriptado si se ha seleccionado esa opción
        if (tamperedMessage) {
            senderMessage =  protocol.intruder(senderMessage);
        }

        // Verificando la firma y mensaje recibidos
        protocol.receiver(senderMessage, rsaInstance, hashInstance, aesInstance, aesKey, ivSpec);
    }
}
