package com.moose.encrypt;

import com.moose.util.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.function.Function;

public class AlgorithmFactory {

    public SymmetricEncryp newTripleDesEcbNopadding() {
        return builder()
                .tripleDES()
                .ecb()
                .noPadding()
                .build();
    }

    public SymmetricEncryp newTripleDesCbcPkcs5padding() {
        return builder()
                .tripleDES()
                .cbc()
                .pkcs5Padding()
                .build();
    }

    public SymmetricEncryp newAesEcbNopadding() {
        return builder()
                .aes()
                .ecb()
                .noPadding()
                .build();
    }

    public SymmetricEncryp newAesEcbPkcs5padding() {
        return builder()
                .aes()
                .ecb()
                .pkcs5Padding()
                .build();
    }


    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private String algorithm = null;
        private String operationMode = null;
        private String padding = null;
        private Function<byte[], SecretKey> keyApply = null;
        private Function<String, byte[]> ivApply = null;

        public Builder des() {
            this.algorithm = "DES";
            this.keyApply = key -> {
                try {
                    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algorithm);
                    return keyFactory.generateSecret(new DESKeySpec(key));
                } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException e) {
                    throw new IllegalArgumentException(e);
                }
            };
            return this;
        }

        public Builder tripleDES() {
            this.algorithm = "DESede";
            this.keyApply = key -> {
                try {
                    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algorithm);
                    return keyFactory.generateSecret(new DESedeKeySpec(key));
                } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException e) {
                    throw new IllegalArgumentException(e);
                }
            };
            return this;
        }

        public Builder aes() {
            this.algorithm = "AES";
            this.keyApply = key -> {
                return new SecretKeySpec(key, algorithm);
            };
            return this;
        }

        public Builder cbc() {
            cbc(null);
            return this;
        }

        public Builder cbc(byte[] iv) {
            this.operationMode = "CBC";
            this.ivApply = transformation -> {
                return iv == null ? initIv(transformation) : iv;
            };
            return this;
        }

        public Builder ecb() {
            this.operationMode = "ECB";
            return this;
        }

        public Builder noPadding() {
            this.padding = "NoPadding";
            return this;
        }

        public Builder pkcs5Padding() {
            this.padding = "PKCS5Padding";
            return this;
        }

        public Builder ios10126Padding() {
            this.padding = "ISO10126Padding";
            return this;
        }

        public SymmetricEncryp build() {
            if(StringUtils.isAnyEmpty(algorithm, operationMode, padding)) {
                throw new IllegalArgumentException("algorithm or operationMode or padding");
            }
            String transformation = StringUtils.join("/", algorithm, operationMode, padding);
            return new SymmetricEncryp(transformation, keyApply, ivApply);
        }

        private byte[] initIv(String fullAlg) {
            try {
                Cipher cipher = Cipher.getInstance(fullAlg);
                int blockSize = cipher.getBlockSize();
                byte[] iv = new byte[blockSize];
                for (int i = 0; i < blockSize; ++i) {
                    iv[i] = 0;
                }
                return iv;
            } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
                throw new IllegalArgumentException(e);
            }
        }
    }
}
