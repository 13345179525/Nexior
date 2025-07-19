package com.example.proxyservice.controller;


import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.example.proxyservice.service.impl.SessionServiceImpl;
import com.example.proxyservice.utils.*;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.annotation.PostConstruct;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Data
@Slf4j
@RestController
@RequestMapping("/login")
public class controller {
    @Value("${security.pubKey}")
    private String pubKey;

    @Value("${security.priKey}")
    private String priKey;

    @Value("${security.iscUrl}")
    private String iscUrl;

    @Autowired
    private SM2Util sm2Util;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    @PostConstruct
    public void init() {
        try {
            publicKey = sm2Util.restorePublicKey(pubKey);
            privateKey = sm2Util.restorePrivateKey(priKey);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Failed to initialize public key", e);
        }
    }

    @Autowired
    private SessionServiceImpl sessionService;

    @Autowired
    private ReplayAttackPreventer replayAttackPreventer;

    private String serPass = "wza2025";


    @CrossOrigin(origins = "*")
    @PostMapping("/testsm2")
    public String testSm2(@RequestBody JSONObject body) {
        try {
            log.info("testSm2 body = {}", body);

            // 1. 从JSON中提取param值
            String encryptedParam = body.getString("param");
            if (encryptedParam == null || encryptedParam.isEmpty()) {
                throw new IllegalArgumentException("请求体中缺少param参数");
            }

            // 2. 使用SM2解密
            String decryptedData = sm2Util.decrypt(encryptedParam, privateKey);
            log.info("decrypted body data = {}", decryptedData);

            // 3. 使用SM2重新加密（测试用）
            String reEncryptedData = sm2Util.encrypt(decryptedData, publicKey);
            log.info("re-encrypted data = {}", reEncryptedData);

            return reEncryptedData;
        } catch (InvalidCipherTextException e) {
            log.error("SM2解密失败", e);
            throw new RuntimeException("解密失败: " + e.getMessage());
        } catch (Exception e) {
            log.error("处理请求时发生错误", e);
            throw new RuntimeException("处理失败: " + e.getMessage());
        }
    }

    @CrossOrigin(origins = "*")
    @GetMapping("/testCheckToken")
    public String testCheckToken(@RequestHeader("token") String token){
        if(validationIscToken(token)){
            return "success";
        }
        return "failed";
    }
    public boolean validationIscToken(String token) {

        try {
            HttpURLConnection connection = (HttpURLConnection) new URL(iscUrl).openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("x-token",token);
            int responseCode = connection.getResponseCode();
            log.info("响应码: {}",responseCode);

            if (responseCode == HttpURLConnection.HTTP_OK) {
                // 使用Java 8 Stream处理响应
                try (Stream<String> lines = new BufferedReader(
                        new InputStreamReader(connection.getInputStream())).lines()) {

                    String response = lines.collect(Collectors.joining("\n"));
                    log.info("响应内容:{}",response);
                    JSONObject jsonObject = JSON.parseObject(response);
                    String result = jsonObject.getString("result");
                    if(Objects.equals(result, "success")){
                        log.info("isc token vaildation success");
                        return true;
                    }
                    log.info("isc token vaildation failed");
                    return false;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    @CrossOrigin(origins = "*")
    @GetMapping("/checkToken")
    public String checkToken(
            @RequestHeader("token") String token,
            @RequestHeader("timeStamp") String timeStamp,
            @RequestHeader("random") String random,
            @RequestHeader("sign") String sign) {
        try {
            log.info("checkout token start");
            // 1. 参数非空校验
            if (token == null || timeStamp == null || random == null || sign == null) {
                Result result = new Result("","header token or timestamp or random or sign is null",1);
                String resSm2Str = sm2Util.encrypt(result.toString(),publicKey);
                return resSm2Str;

            }
            log.info("token = {}, timeStamp = {}, random = {}, sign = {}",token,timeStamp,random,sign);
            if(!validationIscToken(token)){
                log.error("isc token verification failed !!! token = {}",token);
                Result result = new Result("","isc token verification failed",1);
                String resSm2Str = sm2Util.encrypt(result.toString(),publicKey);
                return resSm2Str;
            }
            // 2. 生成服务端签名（保持原MD5逻辑）
            String serverSign = md5Utils.md5(
                    "token=" + token +
                            "&timestamp=" + timeStamp +
                            "&random=" + random +
                            "&secretkey=" + token // 建议secretkey改为独立密钥
            );
            log.info("serverSign success = {}",serverSign);
            // 3. 安全比较签名（避免时序攻击）
            if(!MessageDigest.isEqual(serverSign.getBytes(), sign.getBytes())){
                log.error("security checkout fail serverSign = {}, sign = {}",serverSign,sign);
                Result result = new Result("","sign is error",1);
                String resSm2Str = sm2Util.encrypt(result.toString(),publicKey);
                return resSm2Str;
            }
            log.info("security checkout success");
            String newToken = md5Utils.md5(
                    "token=" + token +
                            "&timestamp=" + System.currentTimeMillis() +
                            "&random=" + UUID.randomUUID() +
                            "&secretkey=" + token // 建议secretkey改为独立密钥
            );
            log.info("newtoken = {}",newToken);
            replayAttackPreventer.insertToken(token,newToken);
            sessionService.recordUserLogin(token,newToken);
            Result result = new Result(newToken,"success",0);
            String resSm2Str = sm2Util.encrypt(result.toString(),publicKey);
            log.info("resSm2Str = {}",resSm2Str);
            return resSm2Str;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    @GetMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("token") String token) {
        replayAttackPreventer.delUser(token);
        return ResponseEntity.ok().build();
    }

}
