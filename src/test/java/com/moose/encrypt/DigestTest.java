package com.moose.encrypt;

import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class DigestTest {

    private byte[] bytes;

    @Before
    public void init() throws UnsupportedEncodingException {
        bytes = "Hello World".getBytes("UTF-8");
    }

    @Test
    public void testMD5() throws IOException {
        byte[] byteExpected = new byte[]{-0x4f, 0xa, -0x73, -0x4f, 0x64, -0x20, 0x75,
                0x41, 0x5, -0x49, -0x57, -0x65, -0x19, 0x2e, 0x3f, -0x1b};
        String hexExpected = "b10a8db164e0754105b7a99be72e3fe5";
        testEncode(Digest.MD5, byteExpected);
        testEncodeHex(Digest.MD5, hexExpected);
    }

    @Test
    public void testSHA1() throws IOException {
        byte[] byteExpected = new byte[]{0xa, 0x4d, 0x55, -0x58, -0x29, 0x78, -0x1b,
                0x2, 0x2f, -0x55, 0x70, 0x19, 0x77, -0x3b, -0x28, 0x40, -0x45, -0x3c, -0x7a, -0x30};
        String hexExpected = "0a4d55a8d778e5022fab701977c5d840bbc486d0";
        testEncode(Digest.SHA1, byteExpected);
        testEncodeHex(Digest.SHA1, hexExpected);
    }

    @Test
    public void testSHA256() throws IOException {
        byte[] byteExpected = new byte[]{-0x5b, -0x6f, -0x5a, -0x2c, 0xb, -0xc, 0x20,
                0x40, 0x4a, 0x1, 0x17, 0x33, -0x31, -0x49, -0x4f, -0x70, -0x2a, 0x2c, 0x65, -0x41, 0xb,
                -0x33, -0x5d, 0x2b, 0x57, -0x4e, 0x77, -0x27, -0x53, -0x61, 0x14, 0x6e};
        String hexExpected = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";
        testEncode(Digest.SHA256, byteExpected);
        testEncodeHex(Digest.SHA256, hexExpected);
    }

    @Test
    public void testSHA384() throws IOException {
        byte[] byteExpected = new byte[]{-0x67, 0x51, 0x43, 0x29, 0x18, 0x6b, 0x2f, 0x6a,
                -0x1c, -0x5f, 0x32, -0x62, 0x7e, -0x1a, -0x3a, 0x10, -0x59, 0x29, 0x63, 0x63, 0x35, 0x17,
                0x4a, -0x3a, -0x49, 0x40, -0x7, 0x2, -0x7d, -0x6a, -0x4, -0x38, 0x3, -0x30, -0x17, 0x38, 0x63,
                -0x59, -0x3d, -0x27, 0xf, -0x7a, -0x42, -0x12, 0x78, 0x2f, 0x4f, 0x3f};
        String hexExpected = "99514329186b2f6ae4a1329e7ee6c610a729636335174ac6b740f9028396fcc803d0e93863a7c3d90f86beee782f4f3f";
        testEncode(Digest.SHA384, byteExpected);
        testEncodeHex(Digest.SHA384, hexExpected);
    }

    @Test
    public void testSHA512() throws IOException {
        byte[] byteExpected = new byte[]{0x2c, 0x74, -0x3, 0x17, -0x13, -0x51, -0x28, 0xe,
                -0x7c, 0x47, -0x50, -0x2c, 0x67, 0x41, -0x12, 0x24, 0x3b, 0x7e, -0x49, 0x4d, -0x2e, 0x14, -0x66,
                0xa, -0x4f, -0x47, 0x24, 0x6f, -0x4d, 0x3, -0x7e, -0xe, 0x7e, -0x7b, 0x3d, -0x7b, -0x7b, 0x71,
                -0x62, 0xe, 0x67, -0x35, -0x26, 0xd, -0x56, -0x71, 0x51, 0x67, 0x10, 0x64, 0x61, 0x5d, 0x64, 0x5a,
                -0x1e, 0x7a, -0x35, 0x15,  -0x41, -0x4f, 0x44, 0x7f, 0x45, -0x65};
        String hexExpected = "2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b";
        testEncode(Digest.SHA512, byteExpected);
        testEncodeHex(Digest.SHA512, hexExpected);
    }

    private void testEncode(Digest digest, byte[] expected) throws IOException {
        byte[] result = digest.hash(bytes);
        assertArrayEquals("Invalid hash", expected, result);

        result = digest.hash(new ByteArrayInputStream(bytes));
        assertArrayEquals("Invalid hash", expected, result);
    }

    private void testEncodeHex(Digest digest, String expected) throws IOException {
        String hash = digest.hashHex(bytes);
        assertEquals("Invalid hash", expected, hash);

        hash = digest.hashHex(new ByteArrayInputStream(bytes));
        assertEquals("Invalid hash", expected, hash);
    }

}
