package com.example.demo.utils;

public class Utils {

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexStringBuffer = new StringBuilder();
        for (byte b : bytes) {
            hexStringBuffer.append(String.format("%02x", b));
        }
        return hexStringBuffer.toString();
    }

    private Utils() {
        //hidden constructor
    }
}
