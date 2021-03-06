package net.inbox.ecdsa;

import net.inbox.sha3.Sha3;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;

/**
 * @author bipin khatiwada
 * github.com/bipinkh
 */
public class Signature {

    public static BigInteger[] messageSign(String msg, BigInteger n, BigInteger p, BigInteger[] G, BigInteger a, BigInteger privateKey) {

        BigInteger k, kInv, r, e, s, z;
        BigInteger[] kG;

        e = new BigInteger(SHASum(msg.getBytes()), 16);
        z = e.shiftRight(e.bitLength() - n.bitLength());

        do {
            do {
                k = BigIntUtils.randomNumberLessThan(p);
                kG = EcOperations.pointMultiply(G, p, a, k);
                r = kG[0].mod(n);
            } while (r.compareTo(BigInteger.ZERO) == 0);

            kInv = k.modInverse(n);

            s = kInv.multiply(z.add(r.multiply(privateKey))).mod(n);

        } while (s.compareTo(BigInteger.ZERO) == 0);

        kG[0] = r;
        kG[1] = s;
        return kG;
    }

    public static boolean messageVerify(String msg, BigInteger[] sign, BigInteger n, BigInteger p, BigInteger[] G, BigInteger a, BigInteger[] pbkQ) {

        BigInteger r = sign[0];
        BigInteger s = sign[1];

        if (r.compareTo(n) >= 0) {
            System.out.println(" r : Message NOT VERIFIED");
            return false;
        }
        if (s.compareTo(n) >= 0) {
            System.out.println(" s :Message NOT VERIFIED");
            return false;
        }

        BigInteger e = new BigInteger(SHASum(msg.getBytes()), 16);
        BigInteger z = e.shiftRight(e.bitLength() - n.bitLength());
        BigInteger sInv = s.modInverse(n);

        BigInteger u1 = z.multiply(sInv).mod(n);
        BigInteger u2 = r.multiply(sInv).mod(n);

        BigInteger[] X = EcOperations.pointAddition(EcOperations.pointMultiply(G, p, a, u1), EcOperations.pointMultiply(pbkQ, p, a, u2), p);

        if(X[0].equals(BigInteger.ZERO) || X[1].equals(BigInteger.ZERO) ){
            System.out.println("Invalid !");
        }
        BigInteger v = X[0].mod(n);

        if (v.compareTo(r) == 0) {
            System.out.println("Message VERIFIED");
            return true;
        }

        System.out.println("Message NOT VERIFIED");
        return false;
    }

    public static String SHASum(byte[] convertMe) {
        Sha3 sha3 = new Sha3(256);
        return byteArray2Hex(sha3.digest(convertMe));
    }

    private static String byteArray2Hex(final byte[] hash) {
        Formatter formatter = new Formatter();
        try{
            for (byte b : hash) {
                formatter.format("%02x", b);
            }
            return formatter.toString();
        }finally {
            formatter.close();
        }

    }

}
