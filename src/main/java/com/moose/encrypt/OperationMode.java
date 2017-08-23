package com.moose.encrypt;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;

public enum OperationMode {

    CBC("CBC", true),

    ECB("ECB", false);

    private final String name;
    private final boolean isNeedParameterSpec;

    private OperationMode(String name, boolean isNeedParameterSpec) {
        this.name = name;
        this.isNeedParameterSpec = isNeedParameterSpec;
    }

    public String getName() {
        return name;
    }

    public boolean isNeedParameterSpec() {
        return isNeedParameterSpec;
    }

    /**
     * 初始向量的方法, 全部为0. 这里的写法适合于其它算法,
     * 针对AES算法的话,IV值一定是128位的(16字节).
     * 针对DES、3DES算法的话,IV值一定是64位的(8字节).
     */
    public byte[] initIv(String fullAlg) {
        if(!isNeedParameterSpec) {
            return null;
        }
        try {
            Cipher cipher = Cipher.getInstance(fullAlg);
            int blockSize = cipher.getBlockSize();
            byte[] iv = new byte[blockSize];
            for (int i = 0; i < blockSize; ++i) {
                iv[i] = 0;
            }
            return iv;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
