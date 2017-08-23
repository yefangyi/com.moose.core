package com.moose.encrypt;

public enum Padding {

    NO_PADDING("NoPadding"),
    PKCS5_PADDING("PKCS5Padding"),
    ISO10126_Padding("ISO10126Padding");

    private final String name;

    private Padding(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

}
