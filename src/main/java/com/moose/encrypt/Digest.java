package com.moose.encrypt;

import org.springframework.util.Assert;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public enum Digest {

    MD5("MD5"),
    SHA1("SHA-1"),
    SHA256("SHA-256"),
    SHA384("SHA-384"),
    SHA512("SHA-512");

    private final String name;
    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    private static final int STREAM_BUFFER_LENGTH = 1024;

    private Digest(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public byte[] hash(byte[] data) {
        Assert.notNull(data, "data must not be null");

        return getDigest(name).digest(data);
    }

    public byte[] hash(InputStream inputStream) throws IOException {
        Assert.notNull(inputStream, "InputStream must not be null ");

        return digest(getDigest(name), inputStream);
    }

    public byte[] hash(String data) {
        Assert.notNull(data, "data must not be null ");

        return hash(data.getBytes(UTF_8));
    }

    public String hashHex(byte[] data) {
        return Hex.encodeHex(hash(data));
    }

    public String hashHex(InputStream data) throws IOException {
        return Hex.encodeHex(hash(data));
    }

    public String hashHex(String data) {
        return Hex.encodeHex(hash(data));
    }

    private MessageDigest getDigest(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private byte[] digest(MessageDigest digest, InputStream inputStream) throws IOException {
        byte[] buffer = new byte[STREAM_BUFFER_LENGTH];
        int bytesRead = -1;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            digest.update(buffer, 0, bytesRead);
        }
        return digest.digest();
    }

}
