package gnu.crypto.cipher;

import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;

import gnu.crypto.Registry;
import gnu.crypto.util.Util;

public final class Shamaq extends BaseCipher {
   private static final int DEFAULT_BLOCK_SIZE = 8; // in bytes
   private static final int DEFAULT_KEY_SIZE = 8; // in bytes
   private static final int ROUNDS = 8;

   private static final byte[] AES_SBOX_BYTES = { (byte) 0x63, (byte) 0x7c,
           (byte) 0x77, (byte) 0x7b, (byte) 0xf2, (byte) 0x6b, (byte) 0x6f,
           (byte) 0xc5, (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2b,
           (byte) 0xfe, (byte) 0xd7, (byte) 0xab, (byte) 0x76, (byte) 0xca,
           (byte) 0x82, (byte) 0xc9, (byte) 0x7d, (byte) 0xfa, (byte) 0x59,
           (byte) 0x47, (byte) 0xf0, (byte) 0xad, (byte) 0xd4, (byte) 0xa2,
           (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, (byte) 0x72, (byte) 0xc0,
           (byte) 0xb7, (byte) 0xfd, (byte) 0x93, (byte) 0x26, (byte) 0x36,
           (byte) 0x3f, (byte) 0xf7, (byte) 0xcc, (byte) 0x34, (byte) 0xa5,
           (byte) 0xe5, (byte) 0xf1, (byte) 0x71, (byte) 0xd8, (byte) 0x31,
           (byte) 0x15, (byte) 0x04, (byte) 0xc7, (byte) 0x23, (byte) 0xc3,
           (byte) 0x18, (byte) 0x96, (byte) 0x05, (byte) 0x9a, (byte) 0x07,
           (byte) 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, (byte) 0x27,
           (byte) 0xb2, (byte) 0x75, (byte) 0x09, (byte) 0x83, (byte) 0x2c,
           (byte) 0x1a, (byte) 0x1b, (byte) 0x6e, (byte) 0x5a, (byte) 0xa0,
           (byte) 0x52, (byte) 0x3b, (byte) 0xd6, (byte) 0xb3, (byte) 0x29,
           (byte) 0xe3, (byte) 0x2f, (byte) 0x84, (byte) 0x53, (byte) 0xd1,
           (byte) 0x00, (byte) 0xed, (byte) 0x20, (byte) 0xfc, (byte) 0xb1,
           (byte) 0x5b, (byte) 0x6a, (byte) 0xcb, (byte) 0xbe, (byte) 0x39,
           (byte) 0x4a, (byte) 0x4c, (byte) 0x58, (byte) 0xcf, (byte) 0xd0,
           (byte) 0xef, (byte) 0xaa, (byte) 0xfb, (byte) 0x43, (byte) 0x4d,
           (byte) 0x33, (byte) 0x85, (byte) 0x45, (byte) 0xf9, (byte) 0x02,
           (byte) 0x7f, (byte) 0x50, (byte) 0x3c, (byte) 0x9f, (byte) 0xa8,
           (byte) 0x51, (byte) 0xa3, (byte) 0x40, (byte) 0x8f, (byte) 0x92,
           (byte) 0x9d, (byte) 0x38, (byte) 0xf5, (byte) 0xbc, (byte) 0xb6,
           (byte) 0xda, (byte) 0x21, (byte) 0x10, (byte) 0xff, (byte) 0xf3,
           (byte) 0xd2, (byte) 0xcd, (byte) 0x0c, (byte) 0x13, (byte) 0xec,
           (byte) 0x5f, (byte) 0x97, (byte) 0x44, (byte) 0x17, (byte) 0xc4,
           (byte) 0xa7, (byte) 0x7e, (byte) 0x3d, (byte) 0x64, (byte) 0x5d,
           (byte) 0x19, (byte) 0x73, (byte) 0x60, (byte) 0x81, (byte) 0x4f,
           (byte) 0xdc, (byte) 0x22, (byte) 0x2a, (byte) 0x90, (byte) 0x88,
           (byte) 0x46, (byte) 0xee, (byte) 0xb8, (byte) 0x14, (byte) 0xde,
           (byte) 0x5e, (byte) 0x0b, (byte) 0xdb, (byte) 0xe0, (byte) 0x32,
           (byte) 0x3a, (byte) 0x0a, (byte) 0x49, (byte) 0x06, (byte) 0x24,
           (byte) 0x5c, (byte) 0xc2, (byte) 0xd3, (byte) 0xac, (byte) 0x62,
           (byte) 0x91, (byte) 0x95, (byte) 0xe4, (byte) 0x79, (byte) 0xe7,
           (byte) 0xc8, (byte) 0x37, (byte) 0x6d, (byte) 0x8d, (byte) 0xd5,
           (byte) 0x4e, (byte) 0xa9, (byte) 0x6c, (byte) 0x56, (byte) 0xf4,
           (byte) 0xea, (byte) 0x65, (byte) 0x7a, (byte) 0xae, (byte) 0x08,
           (byte) 0xba, (byte) 0x78, (byte) 0x25, (byte) 0x2e, (byte) 0x1c,
           (byte) 0xa6, (byte) 0xb4, (byte) 0xc6, (byte) 0xe8, (byte) 0xdd,
           (byte) 0x74, (byte) 0x1f, (byte) 0x4b, (byte) 0xbd, (byte) 0x8b,
           (byte) 0x8a, (byte) 0x70, (byte) 0x3e, (byte) 0xb5, (byte) 0x66,
           (byte) 0x48, (byte) 0x03, (byte) 0xf6, (byte) 0x0e, (byte) 0x61,
           (byte) 0x35, (byte) 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1,
           (byte) 0x1d, (byte) 0x9e, (byte) 0xe1, (byte) 0xf8, (byte) 0x98,
           (byte) 0x11, (byte) 0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94,
           (byte) 0x9b, (byte) 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce,
           (byte) 0x55, (byte) 0x28, (byte) 0xdf, (byte) 0x8c, (byte) 0xa1,
           (byte) 0x89, (byte) 0x0d, (byte) 0xbf, (byte) 0xe6, (byte) 0x42,
           (byte) 0x68, (byte) 0x41, (byte) 0x99, (byte) 0x2d, (byte) 0x0f,
           (byte) 0xb0, (byte) 0x54, (byte) 0xbb, (byte) 0x16
   };

   public Shamaq() {
      super(Registry.SHAMAQ_CIPHER, DEFAULT_BLOCK_SIZE, DEFAULT_KEY_SIZE);
   }

   public Object clone() {
      Shamaq result = new Shamaq();
      result.currentBlockSize = this.currentBlockSize;

      return result;
   }

   public Iterator<Integer> blockSizes() {
      ArrayList<Integer> al = new ArrayList<>();
      al.add(64 / 8);
      al.add(128 / 8);

      return Collections.unmodifiableList(al).iterator();
   }

   public Iterator<Integer> keySizes() {
      ArrayList<Integer> al = new ArrayList<>();
      for (int n = 8; n < 64; n+=2) {
         al.add(n);
      }

      return Collections.unmodifiableList(al).iterator();
   }

   public Object makeKey(byte[] uk, int bs) throws InvalidKeyException {
      final byte[] keyData = new byte[bs * 8]; // TODO: Use SHA-3 later

      final byte[][] roundKeys = new byte[ROUNDS][bs / 2];

      for (int i = 0; i < ROUNDS; i++) {
          System.arraycopy(keyData, (bs / 2) * i, roundKeys[i], 0, bs / 2);
      }

      return roundKeys;
   }

   private byte subByte(byte b) {
      int row = (b >> 4) & 0xf;
      int column = b & 0xf;
      int result = AES_SBOX_BYTES[row * 16 + column] & 0xf;
      return (byte)result;
   }

   private void sub(byte[] data) {
      for (int i = 0; i < data.length; i++) {
         data[i] = subByte(data[i]);
      }
   }

   private void xor(byte[] in1, byte[] in2, byte[] out) {
      for (int i = 0; i < in1.length; i++) {
         out[i] = (byte) ((in1[i] ^ in2[i]) & 0xff);
      }
   }

   private void rotR(byte[] data, int rot) {
      rot %= data.length;
      byte[] temp = Arrays.copyOfRange(data, 0, data.length);

      System.arraycopy(temp, rot, data, 0, data.length - rot);
      System.arraycopy(temp, 0, data, data.length - rot, rot);
   }

   private void round(byte[] in, byte[] out, int bs, byte[] key) {
      byte[] L = Arrays.copyOfRange(in, 0, bs / 2);
      byte[] R = Arrays.copyOfRange(in, bs / 2, bs);

      byte[] Rprime = out;
      xor(R, key, Rprime);
      sub(Rprime);
      rotR(Rprime, key[0]);

      xor(L, Rprime, L);

      System.arraycopy(R, 0, out, 0, bs / 2);
      System.arraycopy(L, 0, out, bs / 2, bs / 2);
   }

   private void reverseLR(byte[] in, byte[] out, int bs) {
      System.arraycopy(in, bs / 2, out, 0, bs / 2);
      System.arraycopy(in, 0, out, bs / 2, bs / 2);
   }

   public void encrypt(byte[] in, int inOffset, byte[] out, int outOffset, Object key, int bs) {
      final byte[][] roundKeys =  (byte[][]) key;

      byte[] tempIn = new byte[bs];
      byte[] tempOut = new byte[bs];
      System.arraycopy(in, inOffset, tempIn, 0, bs);

      for (int i = 0; i < ROUNDS; i++) {
         round(tempIn, tempOut, bs, roundKeys[i]);
         System.arraycopy(tempOut, 0, tempIn, 0, bs);
      }

      reverseLR(tempIn, tempOut, bs);

      System.arraycopy(tempOut, 0, out, outOffset, bs);
   }

   public void decrypt(byte[] in, int inOffset, byte[] out, int outOffset, Object key, int bs) {
      final byte[][] roundKeys = (byte[][]) key;

      byte[] tempIn = new byte[bs];
      byte[] tempOut = new byte[bs];
      System.arraycopy(in, inOffset, tempIn, 0, bs);

      for (int i = ROUNDS; i > 0; i--) {
         round(tempIn, tempOut, bs, roundKeys[i-1]);
         System.arraycopy(tempOut, 0, tempIn, 0, bs);
      }

      reverseLR(tempIn, tempOut, bs);

      System.arraycopy(tempOut, 0, out, outOffset, bs);
   }
}
