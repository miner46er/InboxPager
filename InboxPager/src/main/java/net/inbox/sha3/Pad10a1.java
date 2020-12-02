package net.inbox.sha3;

import net.inbox.BuildConfig;

/**
 * Padding rule pad10*1
 */
public class Pad10a1 implements PaddingRule {
    public Pad10a1() {}

    @Override
    public byte[] pad(int x, int m) {
        int j = -((-m - 2) % x);
        int outbits = 2 + j;
        if (BuildConfig.DEBUG && outbits % 8 != 0) {
            throw new AssertionError("Assertion failed");
        }
        int outbytes = outbits / 8;
        if (BuildConfig.DEBUG && outbytes <= 0) {
            throw new AssertionError("Assertion failed");
        }
        byte[] output = new byte[outbytes];
        // Note endianness: leftmost bit is LSB!
        output[0] = (byte) 0x01; // 0b1...
        output[outbytes - 1] |= 0x80; // ...0b1
        return output;
    }
}
