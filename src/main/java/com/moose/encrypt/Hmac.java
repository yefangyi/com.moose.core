package com.moose.encrypt;

import org.springframework.util.Assert;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public enum Hmac {

    MD5("HmacMD5"),
    SHA1("HmacSHA1"),
    SHA256("HmacSHA256"),
    SHA384("HmacSHA384"),
    SHA512("HmacSHA512");

    private final String name;
    private static final int STREAM_BUFFER_LENGTH = 1024;
    private static final Charset UTF_8 = StandardCharsets.UTF_8;

    private Hmac(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public byte[] hmac(byte[] key, byte[] valueToDigest) {
        Assert.notNull(valueToDigest, "value must be not null");

        try {
            return getInitializedMac(name, key).doFinal(valueToDigest);
        } catch (IllegalStateException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public byte[] hmac(byte[] key, InputStream valueToDigest) throws IOException {
        Assert.notNull(valueToDigest, "value must be not null");

        return updateHmac(getInitializedMac(name, key), valueToDigest).doFinal();
    }

    public byte[] hmac(String key, String valueToDigest) {
        Assert.hasLength(key, "key must be not null");
        Assert.hasLength(valueToDigest, "value must be not null");

        return hmac(key.getBytes(UTF_8), valueToDigest.getBytes(UTF_8));
    }

    public String hmacHex(byte[] key, byte[] valueToDigest) {
        return Hex.encodeHex(hmac(key, valueToDigest));
    }

    public String hmacHex(byte[] key, InputStream valueToDigest) throws IOException {
        return Hex.encodeHex(hmac(key, valueToDigest));
    }

    public String hmacHex(String key, String valueToDigest) {
        return Hex.encodeHex(hmac(key, valueToDigest));
    }

    private Mac getInitializedMac(String algorithm, byte[] key) {
        Assert.notNull(key, "key must be not null");

        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
            Mac mac = Mac.getInstance(algorithm);
            mac.init(keySpec);
            return mac;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private Mac updateHmac(Mac mac, InputStream inputStream) throws IOException {
        mac.reset();
        byte[] buffer = new byte[STREAM_BUFFER_LENGTH];
        int bytesRead = -1;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            mac.update(buffer, 0, bytesRead);
        }
        return mac;
    }

}
