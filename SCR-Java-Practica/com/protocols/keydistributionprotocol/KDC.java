package com.protocols.keydistributionprotocol;


import javax.crypto.SecretKey;

import com.mycompany.basersaexample.Utils;

import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class KDC {

    private SecretKey ka;
    private SecretKey kb;
    private SecretKey ks;

    public KDC(SecretKey ka, SecretKey kb, SecretKey ks) {
        this.ka = ka;
        this.kb = kb;
        this.ks = ks;
    }

    // Getters y setters
    public SecretKey getKa() { return this.ka; }

    public SecretKey getKb() { return this.kb; }

    public SecretKey getKs() { return this.ks; }

    public SecretKey generateKs() throws NoSuchAlgorithmException, NoSuchProviderException {

        SecureRandom random = new SecureRandom();
        SecretKey key = Utils.createKeyForAES(256, random);

        return key;
    }
    
}
