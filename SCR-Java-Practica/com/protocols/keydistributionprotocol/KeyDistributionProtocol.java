package com.protocols.keydistributionprotocol;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.mycompany.basersaexample.Utils;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class KeyDistributionProtocol {

    // ID de A e ID de B
    public static final String ID_A = "123.0.0.3";
    public static final String ID_B = "435.3.2.4";

    // Especificaciones para cifrar con AES/GCM
    public static final int AES_KEY_SIZE = 256;
    public static final int GCM_IV_LENGTH = 12;
    public static final int GCM_TAG_LENGTH = 16;

    public static byte[] concatByteArrays(byte[] b1, byte[] b2) throws IOException {

        byte[] concat = new byte[b1.length + b2.length];

        System.arraycopy(b1, 0, concat, 0, b1.length);
        System.arraycopy(b2, 0, concat, b1.length, b2.length);

        return concat;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
    InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, IOException {

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        // Generar claves maestras de A y B que seran compartidas con el KDC
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_KEY_SIZE);
        
         // Clave para A
        SecretKey ka = kg.generateKey();
        byte[] IV_A = new byte[GCM_IV_LENGTH];
        SecureRandom randomA = new SecureRandom();
        randomA.nextBytes(IV_A);

        // Especificaciones de Ka
        SecretKeySpec keySpecA = new SecretKeySpec(ka.getEncoded(), "AES");

        // Especificaciones de GCM para A
        GCMParameterSpec gcmParameterSpecA = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV_A);
        
         // Clave para B
        SecretKey kb = kg.generateKey();
        byte[] IV_B = new byte[GCM_IV_LENGTH];
        SecureRandom randomB = new SecureRandom();
        randomB.nextBytes(IV_B);

        // Especificaciones de Kb
        SecretKeySpec keySpecB = new SecretKeySpec(kb.getEncoded(), "AES");

        // Especificaciones de GCM para B
        GCMParameterSpec gcmParameterSpecB = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV_B);

        // Instancia del usuario A
        User userA = new User(ka);
        userA.setId(ID_A);

        // Instancia del usuario B
        User userB = new User(kb);
        userB.setId(ID_B);

        // Claves maestras
        System.out.println("Ka: " + ka);
        System.out.println("Kb: " + kb + "\n");


        // (1) A --- ID_A || ID_B || N1 ---> KDC
        // A genera un nonce y crea el primer mensaje
        String N1 = userA.generateNonce();
        String m1 = ID_A + ID_B + N1;

        System.out.println("(1) A --- ID_A || ID_B || N1 ---> KDC");
        System.out.println("\tID A: " + ID_A);
        System.out.println("\tID B: " + ID_B);
        System.out.println("\tNonce N1: " + N1);
        System.out.println("\tMessage 1: " + m1);


        // (2) KDC --- E(Ka, [Ks||ID_A||ID_B||N1]) || E(Kb, [Ks||ID_A]) ---> A
        // El KDC genera una clave de sesion
        SecretKey ks = kg.generateKey();

        // IV para el primer cifrado de Ks
        byte[] IV_S1 = new byte[GCM_IV_LENGTH];
        SecureRandom randomS1 = new SecureRandom();
        randomS1.nextBytes(IV_S1);

        // IV para el segundo cifrado de Ks
        byte[] IV_S2 = new byte[GCM_IV_LENGTH];
        SecureRandom randomS2 = new SecureRandom();
        randomS2.nextBytes(IV_S2);

        // Especificaciones de Ks
        SecretKeySpec keySpecS = new SecretKeySpec(ks.getEncoded(), "AES");

        // Especificaciones de GCM para el primer cifrado de Ks
        GCMParameterSpec gcmParameterSpecS1 = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV_S1);

        // Especificaciones de GCM para el segundo cifrado de Ks
        GCMParameterSpec gcmParameterSpecS2 = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV_S2);

        // Instancia del KDC
        KDC kdc = new KDC(ka, kb, ks);

        // Primera parte del mensaje (Ks || ID_A || ID_B || N1)
        String m2A = ks + m1;
        // Se cifra  con Ka
        cipher.init(Cipher.ENCRYPT_MODE, keySpecA, gcmParameterSpecA);
        byte[] m2AEncrypted = cipher.doFinal(Utils.toByteArray(m2A));

        // Segunda parte del mensaje (Ks || ID_A)
        String m2B = ks + ID_A;
        // Se cifra con Kb
        cipher.init(Cipher.ENCRYPT_MODE, keySpecB, gcmParameterSpecB);
        byte[] m2BEncrypted = cipher.doFinal(Utils.toByteArray(m2B));

        // Se concatenan los dos mensajes cifrados
        byte[] m2Encrypted = concatByteArrays(m2AEncrypted, m2BEncrypted);

        System.out.println("\n(2) KDC --- E(Ka, [Ks||ID_A||ID_B||N1]) || E(Kb, [Ks||ID_A]) ---> A");
        System.out.println("\tKs: " + ks);
        System.out.println("\tMessage 2A:");
        System.out.println("\t\tPlain: " + m2A);
        System.out.println("\t\tEncrypted: " + Utils.toHex(m2AEncrypted));
        System.out.println("\tMessage 2B:");
        System.out.println("\t\tPlain: " + m2B);
        System.out.println("\t\tEncrypted: " + Utils.toHex(m2BEncrypted));
        System.out.println("\tEncrypted message: " + Utils.toHex(m2Encrypted));

        // A desconcatena el bytearray recibido (el mensaje cifrado)
        byte[] m2AReceived = new byte[m2AEncrypted.length];
        byte[] m2BReceived = new byte[m2BEncrypted.length];
        System.arraycopy(m2Encrypted, 0, m2AReceived, 0, m2AEncrypted.length);
        System.arraycopy(m2Encrypted, m2AEncrypted.length, m2BReceived, 0, m2BEncrypted.length);

        // A descifra la primera parte del mensaje con su clave maestra, Ka
        cipher.init(Cipher.DECRYPT_MODE, keySpecA, gcmParameterSpecA);
        byte[] m2ADecrypted = cipher.doFinal(m2AReceived);
        System.out.println("\n\tMessage 2A decrypted: " + Utils.toString(m2ADecrypted));

        // Comprobar que la parte del mensaje cifrado por el KDC con Ka es igual que el descifrado por A con Ka
        if(Utils.toString(m2ADecrypted).equals(m2A)) {
            System.out.println("\t\tKs: " + Utils.toString(m2ADecrypted).substring(0, m2ADecrypted.length - (ID_A.length() + ID_B.length() + N1.length())));
            System.out.println("\t\tID A: " + Utils.toString(m2ADecrypted).substring(m2ADecrypted.length - (ID_A.length() + ID_B.length() + N1.length()), m2ADecrypted.length - (ID_B.length() + N1.length())));
            System.out.println("\t\tID B: " + Utils.toString(m2ADecrypted).substring(m2ADecrypted.length - (ID_B.length() + N1.length()), m2ADecrypted.length - N1.length()));
            System.out.println("\t\tNonce N1: " + Utils.toString(m2ADecrypted).substring(m2ADecrypted.length - N1.length(), m2ADecrypted.length));
            System.out.println("\t[correct decryption]");
        } else {
            System.out.println("\t[incorrect decryption]");
        }


        // (3) A --- E(Kb, [Ks || ID_A]) ---> B
        // A envia la segunda parte del mensaje del KDC a B, y
        // B descifra la parte del mensaje que le corresponde con su clave maestra, Kb
        cipher.init(Cipher.DECRYPT_MODE, keySpecB, gcmParameterSpecB);
        byte[] m2BDecrypted = cipher.doFinal(m2BReceived);

        System.out.println("\n(3) A --- E(Kb, [Ks || ID_A]) ---> B");
        System.out.println("\tEncrypted message: " + Utils.toHex(m2BEncrypted));
        System.out.println("\n\tDecrypted message (message 2B): " + Utils.toString(m2BDecrypted));

        // Comprobar que la parte del mensaje cifrado por el KDC con Kb es igual que el descifrado por B con Kb
        if(Utils.toString(m2BDecrypted).equals(m2B)) {
            System.out.println("\t\tKs: " + Utils.toString(m2BDecrypted).substring(0, m2BDecrypted.length - ID_A.length()));
            System.out.println("\t\tID A: " + Utils.toString(m2BDecrypted).substring(m2BDecrypted.length - ID_A.length(), m2BDecrypted.length));
            System.out.println("\t[correct decryption]");
        } else {
            System.out.println("\t[incorrect decryption]");
        }


        // (4) B --- E(Ks, N2) ---> A
        // B genera el nonce N2
        String N2 = userB.generateNonce();

        // Cifra N2 con la clave de sesion, Ks
        cipher.init(Cipher.ENCRYPT_MODE, keySpecS, gcmParameterSpecS1);
        byte[] N2Encrypted = cipher.doFinal(Utils.toByteArray(N2));

        System.out.println("\n(4) B --- E(Ks, N2) ---> A");
        System.out.println("\tNonce N2: " + N2);
        System.out.println("\tEncrypted message: " + Utils.toHex(N2Encrypted));

        // A descifra el mensaje con Ks y obtiene el nonce N2
        cipher.init(Cipher.DECRYPT_MODE, keySpecS, gcmParameterSpecS1);
        byte[] N2Decrypted = cipher.doFinal(N2Encrypted);

        System.out.println("\n\tDecrypted message: " + Utils.toString(N2Decrypted));

        // Comprobar que el nonce es el mismo
        if(Utils.toString(N2Decrypted).equals(N2)) {
            System.out.println("\t[correct decryption]");
        } else {
            System.out.println("\t[incorrect decryption]");
        }

        // (5) A --- E(Ks, f(N2)) ---> B
        // A realiza una transformacion al nonce N2
        // La transformacion sera darle la vuelta a la cadena
        StringBuilder N2Reverse = new StringBuilder();
        N2Reverse.append(N2);
        N2Reverse = N2Reverse.reverse();
        String N2F = N2Reverse.toString();

        // A cifra con Ks el nonce N2 transformado
        cipher.init(Cipher.ENCRYPT_MODE, keySpecS, gcmParameterSpecS2);
        byte[] N2FEncrypted = cipher.doFinal(Utils.toByteArray(N2F));

        // B descifra con Ks el nonce N2 transformado
        cipher.init(Cipher.DECRYPT_MODE, keySpecS, gcmParameterSpecS2);
        byte[] N2FDecrypted = cipher.doFinal(N2FEncrypted);

        System.out.println("\n(5) A --- E(Ks, f(N2)) ---> B");
        System.out.println("\tReversed nonce (f(N2)): " + N2F);
        System.out.println("\tEncrypted reversed nonce (f(N2)): " + Utils.toHex(N2FEncrypted));
        System.out.println("\n\tDecrypted reversed nonce (f(N2)): " + Utils.toString(N2FDecrypted));

        // B comprueba que el nonce recibido es el nonce que envio al reves
        StringBuilder N2Check = new StringBuilder();
        N2Check.append(Utils.toString(N2FDecrypted));
        N2Check = N2Check.reverse();
        String N2FCheck = N2Check.toString();

        if(N2FCheck.equals(N2)) {
            System.out.println("\t[authenticacion completed]");
        } else {
            System.out.println("\t[error during authentication]");
        }
    }
}