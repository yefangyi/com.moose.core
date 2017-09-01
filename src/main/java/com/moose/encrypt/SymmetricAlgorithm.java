package com.moose.encrypt;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public enum SymmetricAlgorithm {

    DES("DES") {

        @Override
        public SecretKey createSecretKey(byte[] key) {
            try {
                SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(getName());
                return keyFactory.generateSecret(new DESKeySpec(key));
            } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException e) {
                throw new IllegalArgumentException(e);
            }
        }

    },

    TripleDES("DESede") {

        @Override
        public SecretKey createSecretKey(byte[] key) {
            try {
                SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(getName());
                return keyFactory.generateSecret(new DESedeKeySpec(key));
            } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException e) {
                throw new IllegalArgumentException(e);
            }
        }
    },

    AES("AES") {

        @Override
        public SecretKey createSecretKey(byte[] key) {
            return new SecretKeySpec(key, getName());
        }
    };

    private final String name;

    private SymmetricAlgorithm(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public abstract SecretKey createSecretKey(byte[] key);
}
