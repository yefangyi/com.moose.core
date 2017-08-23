package com.moose.encrypt;

import org.springframework.lang.UsesJava8;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

import javax.annotation.Nullable;
import javax.xml.bind.DatatypeConverter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public abstract class Base64 {

    private static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

    private static final Base64Delegate delegate;

    static {
        Base64Delegate delegateToUse = null;
        // JDK 8's java.util.Base64 class present?
        if (ClassUtils.isPresent("java.util.Base64", Base64.class.getClassLoader())) {
            delegateToUse = new JdkBase64Delegate();
        }
        // Apache Commons Codec present on the classpath?
        else if (ClassUtils.isPresent("org.apache.commons.codec.binary.Base64", Base64.class.getClassLoader())) {
            delegateToUse = new CommonsCodecBase64Delegate();
        }
        delegate = delegateToUse;
    }

    private static void assertDelegateAvailable() {
        Assert.state(delegate != null,
                "Neither Java 8 nor Apache Commons Codec found - Base64 encoding between byte arrays not supported");
    }

    public static byte[] encode(@Nullable byte[] src) {
        assertDelegateAvailable();
        return delegate.encode(src);
    }

    public static byte[] decode(@Nullable byte[] src) {
        assertDelegateAvailable();
        return delegate.decode(src);
    }

    public static byte[] encodeUrlSafe(@Nullable byte[] src) {
        assertDelegateAvailable();
        return delegate.encodeUrlSafe(src);
    }

    public static byte[] decodeUrlSafe(@Nullable byte[] src) {
        assertDelegateAvailable();
        return delegate.decodeUrlSafe(src);
    }

    public static String encodeToString(byte[] src) {
        Assert.notNull(src, "src must not be null");

        if (src.length == 0) {
            return "";
        }

        if (delegate != null) {
            // Full encoder available
            return new String(delegate.encode(src), DEFAULT_CHARSET);
        }
        else {
            // JAXB fallback for String case
            return DatatypeConverter.printBase64Binary(src);
        }
    }

    public static byte[] decodeFromString(String src) {
        Assert.notNull(src, "src must not be null");

        if (src.length() == 0) {
            return new byte[0];
        }

        if (delegate != null) {
            // Full encoder available
            return delegate.decode(src.getBytes(DEFAULT_CHARSET));
        }
        else {
            // JAXB fallback for String case
            return DatatypeConverter.parseBase64Binary(src);
        }
    }

    public static String encodeToUrlSafeString(@Nullable byte[] src) {
        assertDelegateAvailable();
        return new String(delegate.encodeUrlSafe(src), DEFAULT_CHARSET);
    }

    public static byte[] decodeFromUrlSafeString(String src) {
        Assert.notNull(src, "src must not be null");
        assertDelegateAvailable();
        return delegate.decodeUrlSafe(src.getBytes(DEFAULT_CHARSET));
    }

    interface Base64Delegate {

        byte[] encode(byte[] src);

        byte[] decode(byte[] src);

        byte[] encodeUrlSafe(byte[] src);

        byte[] decodeUrlSafe(byte[] src);
    }


    @UsesJava8
    static class JdkBase64Delegate implements Base64Delegate {

        @Override
        public byte[] encode(byte[] src) {
            return hasLength(src) ? java.util.Base64.getEncoder().encode(src) : src;
        }

        @Override
        public byte[] decode(byte[] src) {
            return hasLength(src) ? java.util.Base64.getDecoder().decode(src) : src;
        }

        @Override
        public byte[] encodeUrlSafe(byte[] src) {
            return hasLength(src) ? java.util.Base64.getUrlEncoder().encode(src) : src;
        }

        @Override
        public byte[] decodeUrlSafe(byte[] src) {
            return hasLength(src) ? java.util.Base64.getUrlDecoder().decode(src) : src;
        }

        private static boolean hasLength(byte[] src) {
            return src != null && src.length > 0;
        }

    }

    static class CommonsCodecBase64Delegate implements Base64Delegate {

        private final org.apache.commons.codec.binary.Base64 base64 =
                new org.apache.commons.codec.binary.Base64();

        private final org.apache.commons.codec.binary.Base64 base64UrlSafe =
                new org.apache.commons.codec.binary.Base64(0, null, true);

        @Override
        public byte[] encode(byte[] src) {
            return this.base64.encode(src);
        }

        @Override
        public byte[] decode(byte[] src) {
            return this.base64.decode(src);
        }

        @Override
        public byte[] encodeUrlSafe(byte[] src) {
            return this.base64UrlSafe.encode(src);
        }

        @Override
        public byte[] decodeUrlSafe(byte[] src) {
            return this.base64UrlSafe.decode(src);
        }

    }

}
