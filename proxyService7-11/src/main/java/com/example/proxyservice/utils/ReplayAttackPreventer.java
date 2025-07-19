package com.example.proxyservice.utils;

import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

// 基于Redis的分布式nonce校验
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
public class ReplayAttackPreventer {
    private final RedisTemplate<String, String> redisTemplate;
    private final long nonceExpireSeconds;
    private final int EXPIRATION_TIME =  15;
    private final String CLIENT_LOGIN_TOKEN = "clientLoginToken";
    private static final String TOKEN_ZSET_KEY = "tokens:latest";


    public ReplayAttackPreventer(
            RedisTemplate<String, String> redisTemplate,
            @Value("${security.replay.nonce-expire-seconds}") long nonceExpireSeconds) {
        this.redisTemplate = redisTemplate;
        this.nonceExpireSeconds = nonceExpireSeconds;
        log.info("ReplayAttackPreventer initialized with timeout: {} seconds", nonceExpireSeconds);
    }

    public boolean isNonceUsed(String nonce) {
        if (nonce == null || nonce.isEmpty()) {
            return true;
        }

        String key = "nonce:" + nonce;
        try {
            Boolean result = redisTemplate.opsForValue()
                    .setIfAbsent(key, "1", Duration.ofSeconds(nonceExpireSeconds));

            if (result == null) {
                log.error("Redis operation returned null for nonce: {}", nonce);
                return true;
            }
            return !result;
        } catch (Exception e) {
            log.error("Redis operation failed for nonce: {}", nonce, e);
            return true; // 出错时保守处理，拒绝请求
        }
    }



    /**
     * 插入或更新 Token（确保只有一个最新 Token）
     * @param token Token 字符串
     */
    public void insertToken(String clientLoginToken,String token) {
        try {
            // 1. 先删除旧的 Token（如果存在）
            redisTemplate.delete(TOKEN_ZSET_KEY);

            // 2. 插入新 Token，并设置 15 分钟后过期
            long expireTime = System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(EXPIRATION_TIME);
            redisTemplate.opsForZSet().add(TOKEN_ZSET_KEY, token, expireTime);
        } catch (RedisConnectionFailureException e) {
            log.error("Redis连接失败", e);
            throw new RuntimeException("Redis服务不可用", e);
        } catch (Exception e) {
            log.error("Token存储失败", e);
            throw new RuntimeException("系统错误", e);
        }
    }

    public Mono<Void> UpdateToken(String token) {
        try {
            // 1. 先删除旧的 Token（如果存在）
            redisTemplate.delete(TOKEN_ZSET_KEY);
            // 2. 插入新 Token，并设置 15 分钟后过期
            long expireTime = System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(EXPIRATION_TIME);
            redisTemplate.opsForZSet().add(TOKEN_ZSET_KEY, token, expireTime);
        } catch (RedisConnectionFailureException e) {
            log.error("Redis连接失败", e);
            throw new RuntimeException("Redis服务不可用", e);
        } catch (Exception e) {
            log.error("Token存储失败", e);
            throw new RuntimeException("系统错误", e);
        }
        return null;
    }

    public String getClinetLoginToken(String token) {
        log.info("get clinet login token = {}",token);
        return redisTemplate.opsForHash().get(token,CLIENT_LOGIN_TOKEN).toString();
    }

    public long getTokenLastActive(String token) {
        return Long.parseLong(String.valueOf(redisTemplate.opsForHash().get(token,"lastActive")));
    }

    public void delUser(String token){
        redisTemplate.opsForZSet().remove(TOKEN_ZSET_KEY, token);
        Long sizeHash = redisTemplate.opsForHash().size(token);
        if(sizeHash != null && sizeHash == 1) {
            redisTemplate.opsForHash().delete(token);
        }
    }
}