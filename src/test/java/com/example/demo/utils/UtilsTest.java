package com.example.demo.utils;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class UtilsTest {

    @ParameterizedTest
    @MethodSource("parametersTest")
    void byteArrayToStringHexConvertTest(byte[] bytes, String hexExpected) {
        assertEquals(hexExpected, Utils.bytesToHex(bytes));
    }

    private static Stream<Arguments> parametersTest() {
        return Stream.of(
                Arguments.of("".getBytes(), ""),
                Arguments.of("\u0000".getBytes(), "00"),
                Arguments.of("\u1f3d".getBytes(), "e1bcbd"),
                Arguments.of("\u1f3d\u1f5b".getBytes(), "e1bcbde1bd9b")
        );
    }
}
