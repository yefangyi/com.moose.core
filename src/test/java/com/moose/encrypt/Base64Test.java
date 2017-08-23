package com.moose.encrypt;


import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
public class Base64Test {

    @Test
    public void encode() throws UnsupportedEncodingException {
        byte[] bytes = new byte[]
                {-0x4f, 0xa, -0x73, -0x4f, 0x64, -0x20, 0x75, 0x41, 0x5, -0x49, -0x57, -0x65, -0x19, 0x2e, 0x3f, -0x1b};
        assertArrayEquals(bytes, Base64.decode(Base64.encode(bytes)));

        bytes = "你好".getBytes("UTF-8");
        assertArrayEquals(bytes, Base64.decode(Base64.encode(bytes)));

        bytes = "你好\r\n你好".getBytes("UTF-8");
        assertArrayEquals(bytes, Base64.decode(Base64.encode(bytes)));

        bytes = "你好\r\n你好\r\n".getBytes("UTF-8");
        assertArrayEquals(bytes, Base64.decode(Base64.encode(bytes)));

        bytes = new byte[] { (byte) 0xfb, (byte) 0xf0 };
        assertArrayEquals("+/A=".getBytes(), Base64.encode(bytes));
        assertArrayEquals(bytes, Base64.decode(Base64.encode(bytes)));

        assertArrayEquals("-_A=".getBytes(), Base64.encodeUrlSafe(bytes));
        assertArrayEquals(bytes, Base64.decodeUrlSafe(Base64.encodeUrlSafe(bytes)));
    }

    @Test
    public void encodeToStringWithJdk8VsJaxb() throws UnsupportedEncodingException {
        byte[] bytes = new byte[]
                {-0x4f, 0xa, -0x73, -0x4f, 0x64, -0x20, 0x75, 0x41, 0x5, -0x49, -0x57, -0x65, -0x19, 0x2e, 0x3f, -0x1b};
        assertEquals(Base64.encodeToString(bytes), DatatypeConverter.printBase64Binary(bytes));
        assertArrayEquals(bytes, Base64.decodeFromString(Base64.encodeToString(bytes)));
        assertArrayEquals(bytes, DatatypeConverter.parseBase64Binary(DatatypeConverter.printBase64Binary(bytes)));

        bytes = "你好".getBytes("UTF-8");
        assertEquals(Base64.encodeToString(bytes), DatatypeConverter.printBase64Binary(bytes));
        assertArrayEquals(bytes, Base64.decodeFromString(Base64.encodeToString(bytes)));
        assertArrayEquals(bytes, DatatypeConverter.parseBase64Binary(DatatypeConverter.printBase64Binary(bytes)));

        bytes = "你好\r\n你好".getBytes("UTF-8");
        assertEquals(Base64.encodeToString(bytes), DatatypeConverter.printBase64Binary(bytes));
        assertArrayEquals(bytes, Base64.decodeFromString(Base64.encodeToString(bytes)));
        assertArrayEquals(bytes, DatatypeConverter.parseBase64Binary(DatatypeConverter.printBase64Binary(bytes)));

        bytes = "你好\r\n你好\r\n".getBytes("UTF-8");
        assertEquals(Base64.encodeToString(bytes), DatatypeConverter.printBase64Binary(bytes));
        assertArrayEquals(bytes, Base64.decodeFromString(Base64.encodeToString(bytes)));
        assertArrayEquals(bytes, DatatypeConverter.parseBase64Binary(DatatypeConverter.printBase64Binary(bytes)));
    }

    @Test
    public void encodeDecodeUrlSafe() {
        byte[] bytes = new byte[] { (byte) 0xfb, (byte) 0xf0 };
        assertArrayEquals("-_A=".getBytes(), Base64.encodeUrlSafe(bytes));
        assertArrayEquals(bytes, Base64.decodeUrlSafe(Base64.encodeUrlSafe(bytes)));

        assertEquals("-_A=", Base64.encodeToUrlSafeString(bytes));
        assertArrayEquals(bytes, Base64.decodeFromUrlSafeString(Base64.encodeToUrlSafeString(bytes)));
    }

}
