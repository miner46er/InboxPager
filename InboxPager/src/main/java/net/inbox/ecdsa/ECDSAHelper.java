package net.inbox.ecdsa;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ECDSAHelper {
    private static final String PRIVATE_KEY_BEGIN =
            "================BEGIN PRIVATE KEY P192================";
    private static final String PRIVATE_KEY_END =
            "=================END PRIVATE KEY P192=================";
    private static final String PUBLIC_KEY_BEGIN =
            "================BEGIN PUBLIC KEY P192=================";
    private static final String PUBLIC_KEY_END =
            "=================END PUBLIC KEY P192==================";
    private static final String SIGNATURE_BEGIN =
            "===================BEGIN ECDSA P192===================";
    private static final String SIGNATURE_END =
            "====================END ECDSA P192====================";

    private KeyPair keyPair = new KeyPair();

    public void generateKeyPair() {
        keyPair = new KeyPair(Constants.xyG, Constants.p, Constants.a);
    }

    public boolean setPrivateKey(String privateKey) {
        String[] privateKeyParts = privateKey.split("\n");

        if (privateKeyParts.length != 3
                || !privateKeyParts[0].equals(PRIVATE_KEY_BEGIN)
                || !privateKeyParts[2].equals(PRIVATE_KEY_END)) {
            return false;
        }
        keyPair.privateKey = new BigInteger(privateKeyParts[1], 16);

        return true;
    }

    public String getPrivateKey() {
        return PRIVATE_KEY_BEGIN + '\n'
                + keyPair.privateKey.toString(16) + '\n'
                + PRIVATE_KEY_END;
    }

    public boolean setPublicKey(String publicKey) {
        String[] publicKeyParts = publicKey.split("\n");

        if (publicKeyParts.length != 4
                || !publicKeyParts[0].equals(PUBLIC_KEY_BEGIN)
                || !publicKeyParts[3].equals(PUBLIC_KEY_END)) {
            return false;
        }

        keyPair.publicKey = new BigInteger[]{
                new BigInteger(publicKeyParts[1], 16),
                new BigInteger(publicKeyParts[2], 16)
        };

        return true;
    }

    public String getPublicKey() {
        return PUBLIC_KEY_BEGIN + '\n'
                + keyPair.publicKey[0].toString(16) + '\n'
                + keyPair.publicKey[1].toString(16) + '\n'
                + PUBLIC_KEY_END;
    }

    public String signSignatureOnly(String message) {
        if (keyPair.getPrivateKey() == null) {
            return message;
        }

        message = message.trim();

        BigInteger[] signature = Signature.messageSign(message, Constants.n, Constants.p, Constants.xyG, Constants.a, keyPair.getPrivateKey());

        return SIGNATURE_BEGIN + '\n'
                + signature[0].toString(16) + '\n'
                + signature[1].toString(16) + '\n'
                + SIGNATURE_END;
    }

    public String sign(String message) {
        message = message.trim();

        return message + "\n\n"
                + signSignatureOnly(message);
    }

    public boolean verify(String message) {
        if (keyPair.getPublicKey() == null
                || keyPair.getPublicKey()[0] == null
                || keyPair.getPublicKey()[1] == null) {
            return false;
        }

        String[] messageLines = message.trim().split("\n");

        if (!messageLines[messageLines.length - 1].trim().equals(SIGNATURE_END)
                || !messageLines[messageLines.length - 4].trim().equals(SIGNATURE_BEGIN)) {
            return false;
        }

        BigInteger[] signature = new BigInteger[]{
                new BigInteger(messageLines[messageLines.length - 3].trim(), 16),
                new BigInteger(messageLines[messageLines.length - 2].trim(), 16)
        };

        String messageWithoutSignature = String.join("", Arrays.copyOfRange(messageLines, 0, messageLines.length - 4)).trim();
        return Signature.messageVerify(messageWithoutSignature, signature, Constants.n, Constants.p, Constants.xyG, Constants.a, keyPair.getPublicKey());
    }
}
