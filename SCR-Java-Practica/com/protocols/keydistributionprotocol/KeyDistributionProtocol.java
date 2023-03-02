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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
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

        String N1 = null;
        String mensaje1 = null;
        String mensaje2 = null;
        String mensaje3 = null;
        SecretKey ks;
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        // Generar claves maestras de A y B que seran compartidas con el KDC
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_KEY_SIZE);
        
         // Clave para A
        SecretKey ka = kg.generateKey();
        byte[] IV_A = new byte[GCM_IV_LENGTH];
        SecureRandom randomA = new SecureRandom();
        randomA.nextBytes(IV_A);

        // Especificaciones de ka
        SecretKeySpec keySpecA = new SecretKeySpec(ka.getEncoded(), "AES");

        // Especificaciones de GCM para A
        GCMParameterSpec gcmParameterSpecA = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV_A);
        
         // Clave para B
        SecretKey kb = kg.generateKey();
        byte[] IV_B = new byte[GCM_IV_LENGTH];
        SecureRandom randomB = new SecureRandom();
        randomB.nextBytes(IV_B);

        // Especificaciones de kb
        SecretKeySpec keySpecB = new SecretKeySpec(kb.getEncoded(), "AES");

        // Especificaciones de GCM para B
        GCMParameterSpec gcmParameterSpecB = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV_B);

        // Instancia del usuario A
        User userA = new User(ka);
        userA.setId(ID_A);

        // Instancia del usuario B
        User userB = new User(kb);
        userB.setId(ID_B);

        // Instancia del KDC
        KDC kdc = new KDC(ka, kb);

        System.out.println("Ka: " + ka);
        System.out.println("Kb: " + kb + "\n");

        // (1) A --- ID_A || ID_B || N1 ---> KDC
        // A genera un nonce y crea el primer mensaje
        N1 = userA.generateNonce();
        mensaje1 = ID_A + ID_B + N1;

        System.out.println("(1) A --- ID_A || ID_B || N1 ---> KDC");
        System.out.println("\tID_A: " + ID_A);
        System.out.println("\tID_B: " + ID_B);
        System.out.println("\tNonce N1: " + N1);

        // (2) KDC --- E(Ka, [Ks||ID_A||ID_B||N1]) || E(Kb, [Ks||ID_A]) ---> A
        // El KDC genera una clave de sesion
        ks = kdc.generateKs();
        mensaje2 = ks + mensaje1;

        // Se cifra la primera parte del mensaje (Ks||ID_A||ID_B||N1) con Ka
        cipher.init(Cipher.ENCRYPT_MODE, keySpecA, gcmParameterSpecA);
        byte[] mensaje2Bytes = cipher.doFinal(Utils.toByteArray(mensaje2));

        mensaje3 = ks + ID_A;

        // Se cifra la segunda parte del mensaje (Ks||ID_A) con Kb
        cipher.init(Cipher.ENCRYPT_MODE, keySpecB, gcmParameterSpecB);
        byte[] mensaje3Bytes = cipher.doFinal(Utils.toByteArray(mensaje3));

        // Se concatena todo el mensaje
        byte[] concatByteArrays = concatByteArrays(mensaje2Bytes, mensaje3Bytes);

        System.out.println("(2) KDC --- E(Ka, [Ks||ID_A||ID_B||N1]) || E(Kb, [Ks||ID_A]) ---> A");
        System.out.println("\tSession key: " + ks);
        System.out.println("\tEncrypted message: " + Utils.toHex(concatByteArrays));

        // (3) A --- E(Kb, [Ks||ID_A]) ---> B
        // A desconcatena el mensaje recibido
        byte[] b1 = new byte[mensaje2Bytes.length];
        byte[] b2 = new byte[mensaje3Bytes.length];
        System.arraycopy(concatByteArrays, 0, b1, 0, mensaje2Bytes.length);
        System.arraycopy(concatByteArrays, mensaje2Bytes.length, b2, 0, mensaje3Bytes.length);

        // A descifra la primera parte del mensaje con su clave maestra, Ka
        cipher.init(Cipher.DECRYPT_MODE, keySpecA, gcmParameterSpecA);
        byte[] decryptedTextA = cipher.doFinal(b1);
        System.out.println("\tDecrypted message: " + Utils.toString(decryptedTextA));

        // (3) A --- E(Kb, [Ks || ID_A]) ---> B
        // B descifra la parte del mensaje que le corresponde con su clave maestra, Kb
        cipher.init(Cipher.DECRYPT_MODE, keySpecB, gcmParameterSpecB);
        byte[] decryptedTextB = cipher.doFinal(b2);
        System.out.println("(3) A --- E(Kb, [Ks || ID_A]) ---> B");
        System.out.println("\tDecrypted message: " + Utils.toString(decryptedTextB));

        // (4) B --- E(Ks, N2) ---> A


        // (5) A --- E(Ks, f(N2)) ---> B



    }
}