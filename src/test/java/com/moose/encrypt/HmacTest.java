package com.moose.encrypt;

import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class HmacTest {

    private byte[] bytes;
    private byte[] keys;

    @Before
    public void init() throws UnsupportedEncodingException {
        bytes = "Hello World".getBytes("UTF-8");
        keys = "Hello World".getBytes("UTF-8");
    }

    @Test
    public void testHmacMD5() throws IOException {
        byte[] byteExpected = new byte[]{-0x32, 0x5, 0x1f, 0x19, 0x1c, 0x41, 0x6d, 0xd, -0x75, 0x40, -0x25, 0x66, -0x2f, -0x68, -0x5e, -0x28};
        String hexExpected = "ce051f191c416d0d8b40db66d198a2d8";
        testEncode(Hmac.MD5, byteExpected);
        testEncodeHex(Hmac.MD5, hexExpected);

    }

    @Test
    public void testHmacSHA1() throws IOException {
        byte[] byteExpected = new byte[]{0x38, -0x49, -0x35, 0x71, -0x6a, 0x4f, 0x27, 0x37, 0x15, 0x6a,
                0x12, 0x49, -0x7f, 0x31, 0x1, -0x64, -0x66, -0xd, -0x44, -0x1d};
        String hexExpected = "38b7cb71964f2737156a12498131019c9af3bce3";
        testEncode(Hmac.SHA1, byteExpected);
        testEncodeHex(Hmac.SHA1, hexExpected);
    }

    @Test
    public void testHmacSHA256() throws IOException {
        byte[] byteExpected = new byte[]{0x78, -0x27, 0x48, 0x65, 0x8, -0x5b, -0x4c, 0x74, 0x44, 0x2e,
                -0x79, -0x6, 0x70, 0x14, 0x33, -0x13, 0x44, -0x57, -0x7d, 0x5f, 0x20, 0x1, -0x40, 0x6e,
                -0x7e, 0x2f, -0x20, -0xa, 0x10, 0x2f, 0x39, 0x28};
        String hexExpected = "78d9486508a5b474442e87fa701433ed44a9835f2001c06e822fe0f6102f3928";
        testEncode(Hmac.SHA256, byteExpected);
        testEncodeHex(Hmac.SHA256, hexExpected);
    }

    @Test
    public void testHmacSHA384() throws IOException {
        byte[] byteExpected = new byte[]{-0x63, -0x4f, -0x24, 0x4, -0xf, 0x7a, 0x22, 0x53, -0x70, -0x44, -0x46, -0x63, -0x30, -0x29, -0x7d,
                -0x60, 0x77, 0x2b, 0x37, 0x72, -0x69, 0x31, -0x32, -0x2d, 0x2b, 0x33, 0x70, -0x30, -0x61, -0x24, 0x52, -0x69, 0x15, -0x66,
                0x47, -0x55, -0x4a, -0x24, 0x4b, -0x74, -0x37, -0x5f, -0x2c, -0x4, 0x67, -0x7d, 0x6f, -0x29};
        String hexExpected = "9db1dc04f17a225390bcba9dd0d783a0772b37729731ced32b3370d09fdc5297159a47abb6dc4b8cc9a1d4fc67836fd7";
        testEncode(Hmac.SHA384, byteExpected);
        testEncodeHex(Hmac.SHA384, hexExpected);
    }

    @Test
    public void testHmacSHA512() throws IOException {
        byte[] byteExpected = new byte[]{-0x11, 0x1, -0x49, -0x2d, 0x6e, -0x12, 0x75, -0x3f, 0x13, -0x6d, -0x1f, -0x17, -0x43, 0x21, -0x15,
                -0x70, -0x79, 0x23, 0x4, -0x69, -0x19, -0x59, 0xf, -0x68, 0x27, -0x21, -0x1d, 0x33, -0x21, 0x15, -0x7b, -0x1a, 0x50, -0x28,
                0x11, -0x78, 0x1a, 0x25, -0x29, -0x39, -0x5b, -0x11, 0x27, -0x50, -0x65, -0x3, 0x0, -0x58, 0x2f, 0x9, 0x62, -0x2, 0x3, 0x3d,
                0x6c, 0x7f, -0x47, 0x52, -0x62, -0x68, 0x20, -0x7a, -0x53, -0x68};
        String hexExpected = "ef01b7d36eee75c11393e1e9bd21eb9087230497e7a70f9827dfe333df1585e650d811881a25d7c7a5ef27b09bfd00a82f0962fe033d6c7fb9529e982086ad98";
        testEncode(Hmac.SHA512, byteExpected);
        testEncodeHex(Hmac.SHA512, hexExpected);
    }

    private void testEncode(Hmac digest, byte[] expected) throws IOException {
        byte[] result = digest.hmac(keys, bytes);
        assertArrayEquals("Invalid hash", expected, result);

        result = digest.hmac(keys, new ByteArrayInputStream(bytes));
        assertArrayEquals("Invalid hash", expected, result);
    }

    private void testEncodeHex(Hmac digest, String expected) throws IOException {
        String hash = digest.hmacHex(keys, bytes);
        assertEquals("Invalid hash", expected, hash);

        hash = digest.hmacHex(keys, new ByteArrayInputStream(bytes));
        assertEquals("Invalid hash", expected, hash);
    }

}
