package com.moose.encrypt;

import org.springframework.util.Assert;

public abstract class Hex {

    private static final char[] HEX_CHARS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    public static String encodeHex(byte[] bytes) {
        Assert.notNull(bytes, "bytes must not be null");

        StringBuilder sb = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            sb.append(HEX_CHARS[(b >> 4) & 0xf]).append(HEX_CHARS[b & 0xf]);
        }
        return sb.toString();
    }

}
