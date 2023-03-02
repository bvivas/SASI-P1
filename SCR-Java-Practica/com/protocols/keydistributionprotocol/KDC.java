package com.protocols.keydistributionprotocol;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.mycompany.basersaexample.Utils;

import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class KDC {

    private SecretKey ka;
    private SecretKey kb;

    public KDC(SecretKey ka, SecretKey kb) {
        this.ka = ka;
        this.kb = kb;
    }

    // Getters y setters
    public SecretKey getKa() { return this.ka; }

    public SecretKey getKb() { return this.kb; }

    public SecretKey generateKs() throws NoSuchAlgorithmException, NoSuchProviderException {

        SecureRandom random = new SecureRandom();
        SecretKey key = Utils.createKeyForAES(256, random);

        return key;
    }
    
}
