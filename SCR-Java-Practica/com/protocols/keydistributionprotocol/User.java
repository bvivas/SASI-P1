package com.protocols.keydistributionprotocol;

import javax.crypto.SecretKey;

public class User {
    
    private String id;
    private SecretKey masterKey;

    public User(String id, SecretKey masterKey) {
        this.id = id;
        this.masterKey = masterKey;
    }

    // Getters y setters
    public String getId() { return this.id; }
    public SecretKey getMasterKey() { return this.masterKey; }

    // Metodos

    /**
     * Genera un nonce a partir de un alfabeto alfanumerico
     * 
     * @return nonce
     */
    public String generateNonce() {

        String alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
        int size = 10;
        StringBuilder sb = new StringBuilder(size);
        int i = 0;

        for(i=0; i < size; i++) {
            int index = (int)(alphabet.length() * Math.random());
            sb.append(alphabet.charAt(index));
        }

        return sb.toString();
    }

    /**
     * Transforma un nonce revirtiendo su secuencia
     * 
     * @param n
     * @return nonce revertido
     */
    public String reverseNonce(String n) {

        StringBuilder nReverse = new StringBuilder();
        nReverse.append(n);
        nReverse = nReverse.reverse();
        String nF = nReverse.toString();

        return nF;
    }
}
