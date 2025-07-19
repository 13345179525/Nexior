package com.example.proxyservice.utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class md5Utils {
    public static String md5(String input) {
        try {
            // 1. 显式指定UTF-8编码
            byte[] bytes = input.getBytes(StandardCharsets.UTF_8);

            // 2. 计算MD5
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md.digest(bytes);

            // 3. 转为十六进制（小写）
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException("MD5 error", e);
        }
    }

    public static void main(String[] args) {
        String str = "token=5f997176c05b048be1394b269d27992b&timestamp=1752146038044&random=e23122da-ffff-4068-b553-e61ba99ea709&secretkey=d97ad68dccc74385790cbaa76f7dd839";

        System.out.println( md5Utils.md5(str));
    }


}
