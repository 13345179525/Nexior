package com.example.proxyservice.utils;
import org.bouncycastle.crypto.engines.SM2Engine;
import lombok.Data;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.stream.IntStream;

@Component
public class SM2Util {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 生成SM2密钥对
     */
    public static KeyPair generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        X9ECParameters sm2ECParameters = GMNamedCurves.getByName("sm2p256v1");
        ECParameterSpec ecParameterSpec = new ECParameterSpec(
                sm2ECParameters.getCurve(),
                sm2ECParameters.getG(),
                sm2ECParameters.getN(),
                sm2ECParameters.getH());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(ecParameterSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * SM2加密
     */
    public static String encrypt(String plainText, PublicKey publicKey) throws InvalidCipherTextException {
        BCECPublicKey bcPubKey = (BCECPublicKey) publicKey;
        ECPublicKeyParameters pubKeyParameters = new ECPublicKeyParameters(
                bcPubKey.getQ(),
                new ECDomainParameters(bcPubKey.getParameters().getCurve(),
                        bcPubKey.getParameters().getG(),
                        bcPubKey.getParameters().getN()));

        SM2Engine engine = new SM2Engine();
        ParametersWithRandom pwr = new ParametersWithRandom(pubKeyParameters, new SecureRandom());
        engine.init(true, pwr);

        byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] cipherBytes = engine.processBlock(plainBytes, 0, plainBytes.length);
        return Base64.getEncoder().encodeToString(cipherBytes);
    }

    public static byte[] encryptByte(String plainText, PublicKey publicKey) throws InvalidCipherTextException {
        BCECPublicKey bcPubKey = (BCECPublicKey) publicKey;
        ECPublicKeyParameters pubKeyParameters = new ECPublicKeyParameters(
                bcPubKey.getQ(),
                new ECDomainParameters(bcPubKey.getParameters().getCurve(),
                        bcPubKey.getParameters().getG(),
                        bcPubKey.getParameters().getN()));

        SM2Engine engine = new SM2Engine();
        ParametersWithRandom pwr = new ParametersWithRandom(pubKeyParameters, new SecureRandom());
        engine.init(true, pwr);

        byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
        return engine.processBlock(plainBytes, 0, plainBytes.length);
    }

    /**
     * SM2解密
     */
    public static String decrypt(String cipherText, PrivateKey privateKey) throws InvalidCipherTextException {
        BCECPrivateKey bcPrivKey = (BCECPrivateKey) privateKey;
        ECPrivateKeyParameters privKeyParameters = new ECPrivateKeyParameters(
                bcPrivKey.getD(),
                new ECDomainParameters(bcPrivKey.getParameters().getCurve(),
                        bcPrivKey.getParameters().getG(),
                        bcPrivKey.getParameters().getN()));

        SM2Engine engine = new SM2Engine();
//        // 2. 创建SM2引擎并初始化
////        SM2Engine engine = new SM2Engine(mode == SM2Mode.C1C3C2 ?
////                SM2Engine.Mode.C1C3C2 : SM2Engine.Mode.C1C2C3);
        engine.init(false, privKeyParameters);

        byte[] cipherBytes = Base64.getDecoder().decode(cipherText);
        byte[] plainBytes = engine.processBlock(cipherBytes, 0, cipherBytes.length);
        return new String(plainBytes, StandardCharsets.UTF_8);
    }

//    public static String decryptHex(String hexCipherText, PrivateKey privateKey) {
//        try {
//            // 1. Hex → Bytes
//            byte[] cipherBytes = Hex.decode(hexCipherText);
//
//            // 2. 初始化 SM2 引擎
//            BCECPrivateKey bcPrivKey = (BCECPrivateKey) privateKey;
//            ECPrivateKeyParameters privKeyParams = new ECPrivateKeyParameters(
//                    bcPrivKey.getD(),
//                    new ECDomainParameters(
//                            bcPrivKey.getParameters().getCurve(),
//                            bcPrivKey.getParameters().getG(),
//                            bcPrivKey.getParameters().getN()));
//
//            SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2); // 必须与加密端一致
//            engine.init(false, privKeyParams);
//
//            // 3. 解密
//            byte[] plainBytes = engine.processBlock(cipherBytes, 0, cipherBytes.length);
//            return new String(plainBytes, StandardCharsets.UTF_8);
//        } catch (Exception e) {
//            throw new RuntimeException("SM2 解密失败", e);
//        }
//    }

    public static String decryptTest(byte[] cipherText, PrivateKey privateKey) throws InvalidCipherTextException {
        BCECPrivateKey bcPrivKey = (BCECPrivateKey) privateKey;
        ECPrivateKeyParameters privKeyParameters = new ECPrivateKeyParameters(
                bcPrivKey.getD(),
                new ECDomainParameters(bcPrivKey.getParameters().getCurve(),
                        bcPrivKey.getParameters().getG(),
                        bcPrivKey.getParameters().getN()));

        SM2Engine engine = new SM2Engine();
        // 2. 创建SM2引擎并初始化
//        SM2Engine engine = new SM2Engine(mode == SM2Mode.C1C3C2 ?
//                SM2Engine.Mode.C1C3C2 : SM2Engine.Mode.C1C2C3);
        engine.init(false, privKeyParameters);

//        byte[] cipherBytes = Base64.getDecoder().decode(cipherText);
        byte[] plainBytes = engine.processBlock(cipherText, 0, cipherText.length);
        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    /**
     * 从Base64编码字符串恢复公钥
     */
    public static PublicKey restorePublicKey(String publicKeyBase64) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyBase64);
        X9ECParameters sm2ECParameters = GMNamedCurves.getByName("sm2p256v1");
        ECParameterSpec ecParameterSpec = new ECParameterSpec(
                sm2ECParameters.getCurve(),
                sm2ECParameters.getG(),
                sm2ECParameters.getN(),
                sm2ECParameters.getH());

        ECPoint ecPoint = sm2ECParameters.getCurve().decodePoint(keyBytes);
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        return keyFactory.generatePublic(ecPublicKeySpec);
    }

    /**
     * 从Base64编码字符串恢复私钥
     */
    public static PrivateKey restorePrivateKey(String privateKeyBase64) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Base64.getDecoder().decode(privateKeyBase64);
        X9ECParameters sm2ECParameters = GMNamedCurves.getByName("sm2p256v1");
        ECParameterSpec ecParameterSpec = new ECParameterSpec(
                sm2ECParameters.getCurve(),
                sm2ECParameters.getG(),
                sm2ECParameters.getN(),
                sm2ECParameters.getH());

        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(new java.math.BigInteger(1, keyBytes), ecParameterSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        return keyFactory.generatePrivate(ecPrivateKeySpec);
    }

    /**
     * 获取公钥的Base64编码字符串
     */
    public static String getPublicKeyBase64(PublicKey publicKey) {
        BCECPublicKey bcPubKey = (BCECPublicKey) publicKey;
        return Base64.getEncoder().encodeToString(bcPubKey.getQ().getEncoded(false));
    }

    /**
     * 获取私钥的Base64编码字符串
     */
    public static String getPrivateKeyBase64(PrivateKey privateKey) {
        BCECPrivateKey bcPrivKey = (BCECPrivateKey) privateKey;
        return Base64.getEncoder().encodeToString(bcPrivKey.getD().toByteArray());
    }

    /**
     * 将 Hex 字符串转换为 Base64 字符串
     */
    public static String hexToBase64(String hexStr) {
        // 1. Hex → Bytes
        byte[] bytes = hexToBytes(hexStr);
        // 2. Bytes → Base64
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * Hex 字符串 → 字节数组
     */
    private static byte[] hexToBytes(String hexStr) {
        int len = hexStr.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexStr.charAt(i), 16) << 4)
                    + Character.digit(hexStr.charAt(i + 1), 16));
        }
        return data;
    }

    public static String decryptTests(byte[] cipherBytes, PrivateKey privateKey) throws Exception {
        BCECPrivateKey bcPrivKey = (BCECPrivateKey) privateKey;
        ECPrivateKeyParameters privKeyParams = new ECPrivateKeyParameters(
                bcPrivKey.getD(),
                new ECDomainParameters(
                        bcPrivKey.getParameters().getCurve(),
                        bcPrivKey.getParameters().getG(),
                        bcPrivKey.getParameters().getN()));

        SM2Engine engine = new SM2Engine();
        engine.init(false, privKeyParams);

//        byte[] cipherBytes = Base64.getDecoder().decode(base64CipherText);
        byte[] plainBytes = engine.processBlock(cipherBytes, 0, cipherBytes.length);
        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    public static byte[] hexStringToByteArray(String hex) {
        return new BigInteger(hex, 16).toByteArray();
    }





    public static void main(String[] args) throws Exception {
//
////         1. 生成密钥对
////        KeyPair keyPair = generateKeyPair();
////        PublicKey publicKey = keyPair.getPublic();
////        PrivateKey privateKey = keyPair.getPrivate();
        String pubKey =  "BBefIIZ2z/VJsuGI2Qm6B4OQx59yHCptfH3abxWjS/4byrghhuO9+F1yBCqTka+/rTz/TjQluleBz0deLT82R+k=";
        String  priKey = "O41wC4apYzBFSP/NBrfs5tysQJUQekoUZGN/Kz1ixsU=";
        PublicKey publicKey = restorePublicKey(pubKey);
        PrivateKey privateKey = restorePrivateKey(priKey);
        System.out.println("公钥: " + getPublicKeyBase64(publicKey));
        System.out.println("私钥: " + getPrivateKeyBase64(privateKey));
        String hexString = "BIK2RChDJwAPTvSDzxZQcBIIPWn6Gmj3s/iMVXQB2+lhGhQCId+lAEVnZZO79ThfL6KEHY3rOQNDCRpKj4HtjesZNVSCS52nv5e5py2Xen9w2qO28wKpvbwOMmqFWPxsO9SXuiULeLGjDxgH+2OEgzs2jZLlLAeRWi7+LtnLs6dSduGN";
//        String hexString = "BD1TIE8xHDqZlAr20nsFD3yXIeR78D0HNbYDV8E0lw5kZ05GMlu88NLNr28OvbleNjkN3bZ3JTgZ37AUdBIWoqTybmIyb/ZsTa8HjU/DOxj3Ccv8ZzHwO0HmRxfonQ1id/lCvcuZ8n2uN/BtISOMfPJj1kBX";
        String res = decrypt(hexString,privateKey);
        System.out.println(res);
        // 2. 加密测试
//        String plainText = "{\"privateDTO\":{\"devType\":\"aabb\",\"page\":10,\"perPage\":20}}";
//        System.out.println("原始数据: " + plainText);
//        String plainText = "{\"aa\":1,\"bbb\":\"112\"}";
//        System.out.println("原始数据: " + plainText);
//        String cipherText = encrypt(plainText, publicKey);
//        System.out.println("加密结果: " + cipherText);
//        String str = "BDlMfw3nn4ObHXTgySHfW2tmZHuxF2RyeTJU5uwC16At08ZcCGFtgN/Gy3KUgSUQbzPyUCj6yQdRNBuZjOQZ39XFB9mFp9iPMkSx/8cgZEvqBqTlvZpQLfr2Y/O0OCwAIRitsiNq3rlG8oS2SQ88hseYLZSve7oLjMLIyj1YB4MsZMZkq1LvA0V8ktHy/yyyg8MV90rYhqnvk7suWgUhtLtzGr33u6QQN2ldxA==";
//        String aaa = "7/7CnMfRMulKbQsj3Q48Th5Hp+0gevpY/bOAfl5WN+EeQB/ixR+z7IAtlKlNI8hCZx863p4TK3ZsFBXMtAaj5VnRpiBBHhpwBKnngITILl1D9c9vP5stAkKF9yXl6NqsUuWL3qu1piBSdYFXMpm55QNWtT4=";
//        byte[] aaa = "effec29cc7d132e94a6d0b23dd0e3c4e1e47a7ed207afa58fdb3807e5e5637e11e401fe2c51fb3ec802d94a94d23c842671f3ade9e132b766c1415ccb406a3e559d1a620411e1a7004a9e78084c82e5d43f5cf6f3f9b2d024285f725e5e8daac52e58bdeabb5a620527581573299b9e50356b53e".getBytes();
//        // 3. 解密测试
        String aaa = "BP4L8qjdPY7uiQr99GMwDDgGrUOFr69TI7NGfbJ7jwYBebCI+Reu/KLEtXI7jR+xtjG0ZYJR7WAY3C7QCV5npqnmEuQ7zeQ9tw+fqL2J35wYT+wbv5zzybJo0GXwrAKsrtAo+pbQ+SNLWuVZZHFGKEKmB9g2Z6MilYbC2WClVPLrrmQmwtwDV4jiCZDfbqrKPJJeHeLb+2veJpDS5m1/1Zrv4ww=";
        String decryptedText = decrypt(aaa, privateKey);
        System.out.println("解密结果: " + decryptedText);
//        System.out.println(privateKey);
        // 4. 测试密钥恢复
//        PrivateKey restoredPrivateKey = restorePrivateKey(getPrivateKeyBase64(privateKey));
//        System.out.println("Pri = "+ restoredPrivateKey);
//        System.out.println("使用恢复的密钥解密: " + decrypt(str, restoredPrivateKey));
    }

}