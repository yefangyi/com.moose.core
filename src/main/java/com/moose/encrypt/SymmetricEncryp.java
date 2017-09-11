package com.moose.encrypt;

import org.springframework.util.Assert;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.function.Function;

public class SymmetricEncryp {

    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    private String algorithm;
    private byte[] iv = null;
    private Function<byte[], SecretKey> keyApply = null;

    public SymmetricEncryp(String algorithm, Function<byte[], SecretKey> keyApply, Function<String, byte[]> ivApply) {
        this.algorithm = algorithm;
        this.keyApply = keyApply;
        this.iv = ivApply == null ? null : ivApply.apply(algorithm);
    }

    public SymmetricEncryp(String algorithm, Function<byte[], SecretKey> keyApply) {
        this(algorithm, keyApply, null);
    }

    /**
     * 加密函数
     */
    public byte[] encrypt(byte[] data, byte[] key) {
        Assert.notNull(data, "data must be not null");
        Assert.notNull(key, "key must be not null");

        return crypt(data, key, Cipher.ENCRYPT_MODE);
    }

    /**
     * 加密函数
     */
    public byte[] encrypt(String data, String key) {
        Assert.hasLength(data, "data must be not null");
        Assert.hasLength(key, "key must be not null");

        return encrypt(data.getBytes(UTF_8), key.getBytes(UTF_8));
    }

    /**
     * 加密函数
     */
    public String encryptHex(String data, String key) {
        return Base64.encodeToString(encrypt(data, key));
    }

    /**
     * 解密函数
     */
    public byte[] decrypt(byte[] data, byte[] key) {
        Assert.notNull(data, "data must be not null");
        Assert.notNull(key, "key must be not null");

        return crypt(data, key, Cipher.DECRYPT_MODE);
    }

    /**
     * 解密函数
     */
    public String decryptHex(byte[] data, byte[] key) {
        return new String(decrypt(data, key), UTF_8);
    }

    /**
     * 解密函数
     */
    public String decryptHex(String data, String key) {
        Assert.notNull(data, "data must be not null");
        Assert.notNull(key, "key must be not null");

        return decryptHex(Base64.decodeFromString(data), key.getBytes(UTF_8));
    }

    private byte[] crypt(byte[] data, byte[] key, int mode) {
        Assert.hasLength(algorithm);
        try {
            SecretKey secretKey = keyApply.apply(key);
            Cipher cipher = Cipher.getInstance(algorithm);
            if(isNeedParameterSpec(algorithm)) {
                cipher.init(mode, secretKey, new IvParameterSpec(iv));
            } else {
                cipher.init(mode, secretKey, new SecureRandom());
            }
            return cipher.doFinal(data);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException(e);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new IllegalStateException(e);
        }
    }

    private boolean isNeedParameterSpec(String algorithm) {
        return algorithm.indexOf("CBC") > 0;
    }

}
