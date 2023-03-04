package com.protocols.keydistributionprotocol;


import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class KDC {

    private SecretKey ka;
    private SecretKey kb;

    // Especificaciones para cifrar con AES/GCM
    public static final int AES_KEY_SIZE = 256;
    public static final int GCM_IV_LENGTH = 12;
    public static final int GCM_TAG_LENGTH = 16;

    public KDC(SecretKey ka, SecretKey kb) {
        this.ka = ka;
        this.kb = kb;
    }

    // Getters y setters
    public SecretKey getKa() { return this.ka; }
    public SecretKey getKb() { return this.kb; }

    // Metodos

    /**
     * Genera una clave simetrica para AES
     * 
     * @return clave simetrica
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public SecretKey generateKs() throws NoSuchAlgorithmException, NoSuchProviderException {

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_KEY_SIZE);

        SecretKey ks = kg.generateKey();

        return ks;
    }
    
    /**
     * Genera un IV
     * 
     * @return IV
     */
    public byte[] generateIV() {
        
        byte[] IV = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(IV);

        return IV;
    }

    /**
     * Genera una espicifacion de la clave Ks para AES
     * 
     * @return especificacion de Ks
     */
    public SecretKeySpec generateKsSpec(SecretKey ks) {

        SecretKeySpec keySpec = new SecretKeySpec(ks.getEncoded(), "AES");

        return keySpec;
    }

    /**
     * Genera el set de parametros para GCM con el IV
     * 
     * @return set de parametros
     */
    public GCMParameterSpec generateGCMParameterSpec(byte[] IV) {

        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);

        return gcmParameterSpec;
    }
}
