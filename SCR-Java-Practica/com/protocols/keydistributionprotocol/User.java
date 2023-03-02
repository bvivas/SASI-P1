package com.protocols.keydistributionprotocol;

import javax.crypto.SecretKey;

public class User {
    
    private String id;
    private SecretKey masterKey;

    public User(SecretKey masterKey) {
        this.id = null;
        this.masterKey = masterKey;
    }

    // Getters y setters
    public String getId() { return this.id; }
    public void setId(String id) { this.id = id; }

    public SecretKey getMasterKey() { return this.masterKey; }

    // Generar nonces
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
}
