package com.example.proxyservice.service.impl;

import com.example.proxyservice.service.SessionService;
import com.example.proxyservice.utils.ReplayAttackPreventer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.*;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.springframework.data.domain.Range;
@Service
@Slf4j
@RequiredArgsConstructor
public class SessionServiceImpl implements SessionService {
    private final RedisTemplate<String, String> stringRedisTemplate;
    private final ReactiveRedisTemplate<String, String> reactiveStringRedisTemplate;
    private final ReactiveRedisTemplate<String, Object> reactiveObjectRedisTemplate;

    @Value("${gateway.session.timeout:3600}")
    private long sessionTimeoutSeconds;

    @Value("${gateway.token-timeout:15}")
    private long tokenTimeout;

    private String serverToken;

    @Autowired
    private ReplayAttackPreventer replayAttackPreventer;

    private static final String SESSION_CLEANUP_LOCK = "session:cleanup:lock";
    private static final String TOKEN_ZSET_KEY = "tokens:latest";
    private static final String LAST_ACTIVE = "lastActive";
    private static final String CLIENT_LOGIN_TOKEN = "clientLoginToken";
    private static final Duration LOCK_TIMEOUT = Duration.ofMinutes(5);
    private static final long CLEANUP_THRESHOLD_MINUTES = 1;
    private static final long SESSION_EXPIRE_MINS = 15;
    @Override
    public void recordUserLogin(String clientLoginToken, String token) {
        if (token == null || clientLoginToken == null) {
            throw new IllegalArgumentException("参数不能为null");
        }

        if (Boolean.TRUE.equals(stringRedisTemplate.hasKey(token))) {
            log.info("session record user login update activity");
            updateActivity(token);
            return;
        }
        log.info("session record user login create activity");
        Map<String, String> userInfo = new HashMap<>();
        userInfo.put(LAST_ACTIVE, String.valueOf(System.currentTimeMillis()));
        userInfo.put("clientLoginToken", clientLoginToken);

        stringRedisTemplate.execute(new SessionCallback<List<Object>>() {
            @Override
            public List<Object> execute(RedisOperations operations) throws DataAccessException {
                operations.multi();
                operations.opsForHash().putAll(token, userInfo);
                operations.expire(token, SESSION_EXPIRE_MINS, TimeUnit.MINUTES);
                return operations.exec();
            }
        });
    }
    @Override
    public Mono<Void> updateActivity(String token) {
        if (token == null) {
            return Mono.error(new IllegalArgumentException("Token cannot be null"));
        }

        long currentTime = System.currentTimeMillis();
        return Mono.zip(
                reactiveStringRedisTemplate.opsForHash().put(token, LAST_ACTIVE, String.valueOf(currentTime)),
                reactiveStringRedisTemplate.expire(token, Duration.ofSeconds(sessionTimeoutSeconds)),
                reactiveStringRedisTemplate.opsForZSet().add(TOKEN_ZSET_KEY, token, currentTime + (tokenTimeout * 60 * 1000))
        ).then();
    }

    @Override
    public Mono<Void> handleLogout() {
        if (serverToken == null) {
            return Mono.error(new IllegalStateException("No server token available for logout"));
        }

        return Mono.zip(
                        reactiveStringRedisTemplate.delete(serverToken),
                        reactiveStringRedisTemplate.opsForZSet().remove(TOKEN_ZSET_KEY, serverToken)
                )
                .doOnSuccess(v -> log.info("User logged out successfully: {}", serverToken))
                .doOnError(e -> log.error("Logout failed for token: {}", serverToken, e))
                .then();
    }

    @Scheduled(fixedRateString = "${gateway.schedule.tokenCleanupInterval}")
    public void cleanExpiredSessions() {
        Mono.fromRunnable(() -> log.info("开始执行过期会话清理任务..."))
                .then(doCleanup())
                .subscribe(
                        v -> log.info("会话清理任务完成"),
                        e -> log.error("会话清理任务失败", e)
                );
    }


    private Mono<Void> doCleanup() {
        long expiryThreshold = System.currentTimeMillis() - (tokenTimeout * 60 * 1000);

        return reactiveStringRedisTemplate.opsForZSet().rangeWithScores(TOKEN_ZSET_KEY, Range.unbounded())
                .flatMap(tuple -> processToken(tuple, expiryThreshold))
                .then()
                .onErrorResume(e -> {
                    log.error("清理任务执行异常", e);
                    return Mono.empty();
                });
    }
    private Mono<Void> processToken(ZSetOperations.TypedTuple<String> tuple, long expiryThreshold) {
        if (tuple == null || tuple.getValue() == null) {
            return Mono.empty();
        }

        String token = tuple.getValue();
        Double score = tuple.getScore();
        // 将科学计数法的score转为完整数字字符串
        long loginTime = score != null ? Math.round(score) : 0L;
        log.info("redis cleanExpiredSessions process token = {}, score = {}",token,loginTime);
        return reactiveStringRedisTemplate.opsForHash().get(token, LAST_ACTIVE)
                .flatMap(lastActiveObj -> handleTokenWithLastActive(token, loginTime, lastActiveObj, expiryThreshold))
                .switchIfEmpty(Mono.defer(() -> handleTokenWithoutLastActive(token, loginTime, expiryThreshold)))
                .onErrorResume(e -> {
                    log.error("processToken Token error: {}", token, e);
                    return Mono.empty();
                });
    }

    private Mono<Void> handleTokenWithLastActive(String token, long loginTime, Object lastActiveObj, long expiryThreshold) {
        // 1. 参数校验
        if (token == null || lastActiveObj == null) {
            log.warn("Invalid token/lastActiveObj - tokenNull: {}, lastActiveNull: {}",
                    token == null, lastActiveObj == null);
            return Mono.empty();
        }

        // 2. 安全解析
        return Mono.fromCallable(() -> {
                    long lastActive = parseLastActiveTime(lastActiveObj);
                    log.debug("Session check - Token: {}..., login: {}, lastActive: {}",
                            token.substring(0, 4), loginTime, lastActive);

                    if (lastActive >= expiryThreshold) {
                        return "UPDATE";
                    } else if (loginTime - (tokenTimeout * 60_000) < expiryThreshold) {
                        return "DELETE";
                    }
                    return "NOOP";
                })
                .flatMap(op -> {
                    switch (op) {
                        case "UPDATE":
                            return replayAttackPreventer.UpdateToken(token)
                                    .onErrorResume(e -> {
                                        log.error("Update token failed: {}...", token.substring(0, 4), e);
                                        return Mono.empty();
                                    });
                        case "DELETE":
                            return deleteToken(token);
                        default:
                            return Mono.empty();
                    }
                })
                .onErrorResume(e -> {
                    log.error("Session processing failed: {}... Cause: {}",
                            token.substring(0, 4), e.getMessage());
                    return Mono.empty();
                });
    }

//    private long parseLastActiveTime(Object obj) {
//        try {
//            if (obj instanceof Number) {
//                return ((Number) obj).longValue();
//            }
//            return Long.parseLong(obj.toString());
//        } catch (Exception e) {
//            log.warn("Invalid lastActive time: {}", obj, e);
//            return 0L;
//        }
//    }

    /**
     * 安全解析最后活跃时间
     */
    private long parseLastActiveTime(Object lastActiveObj) {
        try {
            if (lastActiveObj == null) {
                log.warn("lastActiveObj is null");
                return 0L;
            }

            // 处理各种可能的返回类型
            if (lastActiveObj instanceof Number) {
                return ((Number) lastActiveObj).longValue();
            }

            String strValue = lastActiveObj.toString()
                    .replace("\"", "")
                    .trim();

            return strValue.isEmpty() ? 0L : Long.parseLong(strValue);
        } catch (Exception e) {
            log.warn("Failed to parse lastActive time, using default 0. Input: {}", lastActiveObj);
            return 0L;
        }
    }

    private Mono<Void> handleTokenWithoutLastActive(String token, long loginTime, long expiryThreshold) {
        log.info("handleTokenWithoutLastActive");
        return Mono.defer(() -> {
            log.debug("Token {} 没有最后活跃时间记录", token);

            if (loginTime < expiryThreshold) {
                log.info("删除无活跃记录的过期会话: {}", token);
                return deleteToken(token);
            }
            return Mono.empty();
        });
    }

    private Mono<Void> deleteToken(String token) {
        return Mono.zip(
                        reactiveStringRedisTemplate.opsForZSet().remove(TOKEN_ZSET_KEY, token),
                        reactiveStringRedisTemplate.opsForHash().delete(token)
                )
                .then()
                .doOnSuccess(v -> log.debug("success delete Token: {}", token))
                .doOnError(e -> log.error("failed delete Token: {}", token, e));
    }

    @Override
    public Mono<Boolean> validateSession(String token) {
        if (token == null) {
            return Mono.just(false);
        }

        return reactiveStringRedisTemplate.hasKey(token)
                .flatMap(exists -> {
                    if (Boolean.TRUE.equals(exists)) {
                        return updateActivity(token).thenReturn(true);
                    }
                    return Mono.just(false);
                });
    }

    @Override
    public Mono<String> getClientLoginToken(String sessionToken) {
        return reactiveStringRedisTemplate.opsForHash().get(sessionToken, CLIENT_LOGIN_TOKEN)
                .map(Object::toString)
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Session token not found or invalid")));
    }

    private long parseTimestamp(String timestampStr) throws NumberFormatException {
        try {
            return Long.parseLong(timestampStr);
        } catch (NumberFormatException e) {
            String cleaned = timestampStr.replaceAll("[^0-9]", "");
            if (cleaned.length() != 13) {
                throw new NumberFormatException("Timestamp must be 13 digits");
            }
            return Long.parseLong(cleaned);
        }
    }
}