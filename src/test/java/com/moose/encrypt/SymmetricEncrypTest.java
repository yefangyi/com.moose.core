package com.moose.encrypt;

import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class SymmetricEncrypTest {

    @Test
    public void testDES() throws IOException {
        String data = "abcdabcd";
        String key = "Hello World";
        byte[] bytes = data.getBytes("UTF-8");
        byte[] keys = key.getBytes("UTF-8");

        byte[] expected = new byte[]{0x13, -0x69, 0x62, 0x40, -0x59, 0x63, -0x72, -0x18};
        String hexExpected = "E5diQKdjjug=";
        SymmetricEncryp encryp = new SymmetricEncryp(SymmetricAlgorithm.DES, OperationMode.ECB, Padding.NO_PADDING);
        testEncode(encryp, expected, bytes, keys);
        testEncodeHex(encryp, hexExpected, data, key);

        expected = new byte[]{0x13, -0x69, 0x62, 0x40, -0x59, 0x63, -0x72, -0x18, 0x70, -0x3b, 0x76, 0x29, -0x62, -0x33, 0x30, -0x3b};
        hexExpected = "E5diQKdjjuhwxXYpns0wxQ==";
        encryp = new SymmetricEncryp(SymmetricAlgorithm.DES, OperationMode.ECB, Padding.PKCS5_PADDING);
        testEncode(encryp, expected, bytes, keys);
        testEncodeHex(encryp, hexExpected, data, key);

        expected = new byte[]{0x13, -0x69, 0x62, 0x40, -0x59, 0x63, -0x72, -0x18};
        hexExpected = "E5diQKdjjug=";
        encryp = new SymmetricEncryp(SymmetricAlgorithm.DES, OperationMode.CBC, Padding.NO_PADDING);
        testEncode(encryp, expected, bytes, keys);
        testEncodeHex(encryp, hexExpected, data, key);


        expected = new byte[]{0x13, -0x69, 0x62, 0x40, -0x59, 0x63, -0x72, -0x18, -0x57, -0x26, -0x79, -0x29, -0x22, -0x51, 0x3e, 0x6f};
        hexExpected = "E5diQKdjjuip2ofX3q8+bw==";
        encryp = new SymmetricEncryp(SymmetricAlgorithm.DES, OperationMode.CBC, Padding.PKCS5_PADDING);
        testEncode(encryp, expected, bytes, keys);
        testEncodeHex(encryp, hexExpected, data, key);
    }

    @Test
    public void testTripleDES() throws IOException {
        String data = "abcdabcd";
        String key = "abcdabcdabcdabcdabcdabcd";
        byte[] bytes = data.getBytes("UTF-8");
        byte[] keys = key.getBytes("UTF-8");

        byte[] expected = new byte[]{-0x58, -0x34, -0x14, -0x6c, -0x31, 0x7f, 0x5e, -0x74};
        String hexExpected = "qMzslM9/Xow=";
        SymmetricEncryp encryp = new SymmetricEncryp(SymmetricAlgorithm.TripleDES, OperationMode.ECB, Padding.NO_PADDING);
        testEncode(encryp, expected, bytes, keys);
        testEncodeHex(encryp, hexExpected, data, key);

        expected = new byte[]{-0x58, -0x34, -0x14, -0x6c, -0x31, 0x7f, 0x5e, -0x74, 0x30, -0x3c, -0x28, 0x37, -0x5f, -0x48, 0x4c, 0x7f};
        hexExpected = "qMzslM9/XowwxNg3obhMfw==";
        encryp = new SymmetricEncryp(SymmetricAlgorithm.TripleDES, OperationMode.ECB, Padding.PKCS5_PADDING);
        testEncode(encryp, expected, bytes, keys);
        testEncodeHex(encryp, hexExpected, data, key);

        expected = new byte[]{-0x58, -0x34, -0x14, -0x6c, -0x31, 0x7f, 0x5e, -0x74};
        hexExpected = "qMzslM9/Xow=";
        encryp = new SymmetricEncryp(SymmetricAlgorithm.TripleDES, OperationMode.CBC, Padding.NO_PADDING);
        testEncode(encryp, expected, bytes, keys);
        testEncodeHex(encryp, hexExpected, data, key);


        expected = new byte[]{-0x58, -0x34, -0x14, -0x6c, -0x31, 0x7f, 0x5e, -0x74, 0x33, -0x41, 0x61, 0x76, 0x7f, 0x32, -0x10, -0x7b};
        hexExpected = "qMzslM9/Xowzv2F2fzLwhQ==";
        encryp = new SymmetricEncryp(SymmetricAlgorithm.TripleDES, OperationMode.CBC, Padding.PKCS5_PADDING);
        testEncode(encryp, expected, bytes, keys);
        testEncodeHex(encryp, hexExpected, data, key);

    }

    @Test
    public void testAES() throws IOException {
        String data = "abcdabcdabcdabcd";
        String key = "abcdabcdabcdabcd";
        byte[] bytes = data.getBytes("UTF-8");
        byte[] keys = key.getBytes("UTF-8");

        byte[] expected = new byte[]{-0x7f, -0x4d, -0x5a, 0x4, -0x26, 0x5b, -0x49, 0xe, 0x25, 0xf, -0x53, 0x29, 0x16, 0x3c, -0x20, -0x3c};
        String hexExpected = "gbOmBNpbtw4lD60pFjzgxA==";
        SymmetricEncryp encryp = new SymmetricEncryp(SymmetricAlgorithm.AES, OperationMode.ECB, Padding.NO_PADDING);
        testEncode(encryp, expected, bytes, keys);
        testEncodeHex(encryp, hexExpected, data, key);

        expected = new byte[]{-0x7f, -0x4d, -0x5a, 0x4, -0x26, 0x5b, -0x49, 0xe, 0x25, 0xf, -0x53, 0x29, 0x16, 0x3c, -0x20, -0x3c, -0x6a,
                0x2f, -0x73, 0x2, 0x50, 0x51, 0x27, -0x4, 0x26, 0x57, 0x46, 0x10, 0x11, 0x8, 0x50, 0x28};
        hexExpected = "gbOmBNpbtw4lD60pFjzgxJYvjQJQUSf8JldGEBEIUCg=";
        encryp = new SymmetricEncryp(SymmetricAlgorithm.AES, OperationMode.ECB, Padding.PKCS5_PADDING);
        testEncode(encryp, expected, bytes, keys);
        testEncodeHex(encryp, hexExpected, data, key);

        expected = new byte[]{-0x7f, -0x4d, -0x5a, 0x4, -0x26, 0x5b, -0x49, 0xe, 0x25, 0xf, -0x53, 0x29, 0x16, 0x3c, -0x20, -0x3c};
        hexExpected = "gbOmBNpbtw4lD60pFjzgxA==";
        encryp = new SymmetricEncryp(SymmetricAlgorithm.AES, OperationMode.CBC, Padding.NO_PADDING);
        testEncode(encryp, expected, bytes, keys);
        testEncodeHex(encryp, hexExpected, data, key);


        expected = new byte[]{-0x7f, -0x4d, -0x5a, 0x4, -0x26, 0x5b, -0x49, 0xe, 0x25, 0xf, -0x53, 0x29, 0x16, 0x3c, -0x20, -0x3c,
                -0x5e, -0x62, -0x25, 0x47, -0x27, -0x17, -0x3, 0x52, -0x22, 0x4f, -0x31, -0x1f, 0x7b, 0x69, -0x56, 0x5f};
        hexExpected = "gbOmBNpbtw4lD60pFjzgxKKe20fZ6f1S3k/P4Xtpql8=";
        encryp = new SymmetricEncryp(SymmetricAlgorithm.AES, OperationMode.CBC, Padding.PKCS5_PADDING);
        testEncode(encryp, expected, bytes, keys);
        testEncodeHex(encryp, hexExpected, data, key);
    }

    private void testEncode(SymmetricEncryp encryp, byte[] expected, byte[] bytes, byte[] keys) throws IOException {
        assertArrayEquals("Invalid hash", bytes, encryp.decrypt(encryp.encrypt(bytes, keys), keys));
        assertArrayEquals("Invalid hash", expected, encryp.encrypt(bytes, keys));
    }

    private void testEncodeHex(SymmetricEncryp encryp, String expected, String data, String key) throws IOException {
        byte[] keys = key.getBytes("utf-8");
        assertEquals("Invalid hash", data, encryp.decryptHex(encryp.encrypt(data.getBytes("utf-8"), keys), keys));
        assertEquals("Invalid hash", expected, encryp.encryptHex(data, key));
    }

}
