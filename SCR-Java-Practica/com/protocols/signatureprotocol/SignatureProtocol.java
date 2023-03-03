package com.protocols.signatureprotocol;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

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
    public static final int AES_KEY_SIZE = 256;
    public static final int GCM_IV_LENGTH = 12;
    public static final int GCM_TAG_LENGTH = 16;
    // Esta clase contiene todo lo que el emisor envía al receptor
    private class SenderResponse {
        private PublicKey pubKey;
        private byte[] cipheredMessage;
    }

    // Esta función devuelve el mensaje que enviaría un emisor en la conversación con RSA
    public SenderResponse sender(String inputMessage, String rsaInstance, String hashInstance, String aesInstance, SecretKeySpec aesKeySpec, GCMParameterSpec gcmParameterSpec)
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

        // Concatenando el digest cifrado al texto plano
        byte[] fullMessage = new byte[Utils.toByteArray(inputMessage).length + cipherDigest.length];
        System.arraycopy(Utils.toByteArray(inputMessage), 0, fullMessage, 0, Utils.toByteArray(inputMessage).length);
        System.arraycopy(cipherDigest, 0, fullMessage, Utils.toByteArray(inputMessage).length, cipherDigest.length);

        // Cifrando el mensaje con la clave simétrica
        symmetricCipher.init(Cipher.ENCRYPT_MODE, aesKeySpec, gcmParameterSpec);
        byte[] cipheredMessage = symmetricCipher.doFinal(fullMessage);

        // Se muestra el mensaje cifrado
        System.out.println("\nEncrypted message: " + Utils.toHex(cipheredMessage));

        // Definiendo el mensaje del emisor
        SenderResponse response = new SenderResponse();
        response.pubKey = pubKey;
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

        // Modificando mensaje
        senderMessage.cipheredMessage[9] ^= '0' ^ '9';

        // Mostrando el mensaje encriptado modificado
        System.out.println("\nTampered encrypted message: " + Utils.toHex(senderMessage.cipheredMessage));

        // Devolviendo el mensaje modificado
        return senderMessage;
    }

    // Esta función comprueba el mensaje enviado por el emisor para ver que es correcto y la firma auténtica
    public void receiver(SenderResponse senderMessage, String rsaInstance, String hashInstance, String aesInstance, SecretKeySpec aesKeySpec, GCMParameterSpec gcmParameterSpec)
        throws Exception
    {
        // Instanciando cifrados
        Cipher asymmetricCipher = Cipher.getInstance(rsaInstance);
        MessageDigest hash = MessageDigest.getInstance(hashInstance);
        Cipher symmetricCipher = Cipher.getInstance(aesInstance);

        // Mostrando mensaje cabecera del receptor
        System.out.println("\n---------- RECEIVER AREA ----------");

        // Obteniendo la longitud del digest en bytes
        // Produciendo un digest de prueba y encriptándolo con la clave pública para
        // obtener un texto de la misma longitud que el digest encriptado recibido
        hash.update(Utils.toByteArray("Dummy text"));
        byte[] dummyDigest = hash.digest();
        asymmetricCipher.init(Cipher.ENCRYPT_MODE, senderMessage.pubKey);
        byte[] encryptedDummyDigest = asymmetricCipher.doFinal(dummyDigest);
        int encryptedDigestLenght = encryptedDummyDigest.length;
        
        // Descrifrando mensaje recibido con la clave simétrica
        symmetricCipher.init(Cipher.DECRYPT_MODE, aesKeySpec, gcmParameterSpec);
        byte[] decryptedMessage = symmetricCipher.doFinal(senderMessage.cipheredMessage);

        // Separando el digest del mensaje en texto claro
        byte[] receivedDigest = new byte[encryptedDigestLenght];
        byte[] receivedText = new byte[decryptedMessage.length - encryptedDigestLenght];
        System.arraycopy(decryptedMessage, decryptedMessage.length - encryptedDigestLenght, receivedDigest, 0, encryptedDigestLenght);
        System.arraycopy(decryptedMessage, 0, receivedText, 0, receivedText.length);
        
        // Mostrando mensaje descifrado
        System.out.println("\nDecrypted message: " + Utils.toString(receivedText));
        System.out.println("\nEncrypted received digest: " + Utils.toHex(receivedDigest));
        
        // Descifrando el digest con la clave pública
        asymmetricCipher.init(Cipher.DECRYPT_MODE, senderMessage.pubKey);
        byte[] decryptedDigest = asymmetricCipher.doFinal(receivedDigest);
        
        // Mostrando digest descifrado
        System.out.println("\nDecrypted digest: " + Utils.toHex(decryptedDigest));

        // Se obtiene el digest del mensaje descifrado
        hash.update(receivedText);
        byte[] calculatedDigest = hash.digest();
        
        // Se muestra el digest producido
        System.out.println("\nDecrypted message's digest: " + Utils.toHex(calculatedDigest));

        // Comparando digests para comprobar la autenticidad de la firma y la integridad del mensaje
        if (Utils.toHex(decryptedDigest).equals(Utils.toHex(calculatedDigest))) {
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
        String hashInstance = "SHA3-512";
        String aesInstance = "AES/GCM/NoPadding";
        SignatureProtocol protocol = new SignatureProtocol();

        // Instanciando cifrado simétrico
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_KEY_SIZE);
        SecretKey aesKey = kg.generateKey();
        byte[] IV = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(IV);
        SecretKeySpec keySpec = new SecretKeySpec(aesKey.getEncoded(), "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);
        
        // Obteniendo mensaje del emisor
        SenderResponse senderMessage = protocol.sender(input, rsaInstance, hashInstance, aesInstance, keySpec, gcmParameterSpec);

        // Interceptando y modificando el mensaje encriptado si se ha seleccionado esa opción
        if (tamperedMessage) {
            senderMessage =  protocol.intruder(senderMessage);
        }

        // Verificando la firma y mensaje recibidos
        protocol.receiver(senderMessage, rsaInstance, hashInstance, aesInstance, keySpec, gcmParameterSpec);
    }
}
