package com.moose.encrypt;

import com.moose.util.StringUtils;
import org.springframework.util.Assert;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SymmetricEncryp {

    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    private SymmetricAlgorithm algorithm;
    private OperationMode operationMode ;
    private String transformation;
    private byte[] iv = null;

    public SymmetricEncryp(SymmetricAlgorithm algorithm, OperationMode operationMode, Padding padding, byte[] iv) {
        this.algorithm = algorithm;
        this.operationMode = operationMode;
        this.transformation = StringUtils.join("/", algorithm.getName(), operationMode.getName(), padding.getName());
        this.iv = iv != null ? iv: operationMode.initIv(transformation);
    }

    public SymmetricEncryp(SymmetricAlgorithm algorithm, OperationMode operationMode, Padding padding) {
        this(algorithm, operationMode, padding, null);
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
        try {
            SecretKey secretKey = algorithm.createSecretKey(key);
            Cipher cipher = Cipher.getInstance(transformation);
            if(operationMode.isNeedParameterSpec()) {
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

}
