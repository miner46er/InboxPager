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

    public void setPrivateKey(String privateKey) {
        String[] privateKeyParts = privateKey.split("\n");

        if (privateKeyParts.length != 3
                || !privateKeyParts[0].equals(PRIVATE_KEY_BEGIN)
                || !privateKeyParts[2].equals(PRIVATE_KEY_END)) {
            return;
        }
        keyPair.privateKey = new BigInteger(privateKeyParts[1], 16);
    }

    public String getPrivateKey() {
        return PRIVATE_KEY_BEGIN + '\n'
                + keyPair.privateKey.toString(16) + '\n'
                + PRIVATE_KEY_END;
    }

    public String getPublicKey() {
        return PUBLIC_KEY_BEGIN + '\n'
                + keyPair.publicKey[0].toString(16) + '\n'
                + keyPair.publicKey[1].toString(16) + '\n'
                + PUBLIC_KEY_END;
    }

    public void setPublicKey(String publicKey) {
        String[] publicKeyParts = publicKey.split("\n");

        if (publicKeyParts.length != 4
                || !publicKeyParts[0].equals(PUBLIC_KEY_BEGIN)
                || !publicKeyParts[3].equals(PUBLIC_KEY_END)) {
            return;
        }

        keyPair.publicKey = new BigInteger[]{
                new BigInteger(publicKeyParts[1], 16),
                new BigInteger(publicKeyParts[2], 16)
        };
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

    public boolean verify(String message) throws NoSuchAlgorithmException {
        if (keyPair.getPublicKey() == null
                || keyPair.getPublicKey()[0] == null
                || keyPair.getPublicKey()[1] == null) {
            return false;
        }

        String[] messageLines = message.trim().split("\n");

        System.out.println(Arrays.toString(messageLines));

        if (!messageLines[messageLines.length - 1].equals(SIGNATURE_END)
                || !messageLines[messageLines.length - 4].equals(SIGNATURE_BEGIN)) {
            return false;
        }

        BigInteger[] signature = new BigInteger[]{
                new BigInteger(messageLines[messageLines.length - 3], 16),
                new BigInteger(messageLines[messageLines.length - 2], 16)
        };

        System.out.println(signature[0].toString(16));
        System.out.println(signature[1].toString(16));

        String messageWithoutSignature = String.join("", Arrays.copyOfRange(messageLines, 0, messageLines.length - 4));
        return Signature.messageVerify(messageWithoutSignature, signature, Constants.n, Constants.p, Constants.xyG, Constants.a, keyPair.getPublicKey());
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String msg = "this is the formula of coca cola";

        String privateKey = PRIVATE_KEY_BEGIN + '\n'
                + "d7ea1fdda23772d18c9bad02a129f12daeb7f8146237db3b" + '\n'
                + PRIVATE_KEY_END;

        String publicKey = PUBLIC_KEY_BEGIN + '\n'
                + "acca644f97e00e019accbbe9bedabe597550d3d5da45ba5c" + '\n'
                + "ff707398e78c945e5aa4bca4e4fca1d2eebf6ce8af005d16" + '\n'
                + PUBLIC_KEY_END;

        String signatureTest = SIGNATURE_BEGIN + '\n'
                + "36864bd29bb72fa5e8770eeb377e9a2178f1409467ea2b11" + '\n'
                + "e341c637654dadcdb4d4f27d013d9e08daa7bac2e6d15659" + '\n'
                + SIGNATURE_END;

        ECDSAHelper helper = new ECDSAHelper();
        helper.setPrivateKey(privateKey);
        helper.setPublicKey(publicKey);
        String signature = helper.signSignatureOnly(msg);

        String signedMessageTest = msg + "\n\n" + signatureTest;

        System.out.println(helper.verify(signedMessageTest));
    }
}
