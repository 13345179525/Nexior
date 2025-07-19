package com.example.proxyservice.filter;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.example.proxyservice.service.impl.SessionServiceImpl;
import com.example.proxyservice.utils.*;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.reactivestreams.Publisher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import javax.annotation.PostConstruct;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
@Component
public class AuthFilter implements GlobalFilter, Ordered {

    private static final String NONCE_USED_KEY_PREFIX = "nonce:";

    // 配置参数
    @Value("${gateway.rate-limit.global:5000}")
    private int globalRateLimit; // 全局每分钟最大请求数

    @Value("${security.pubKey}")
    private String pubKey;

    @Value("${security.priKey}")
    private String priKey;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    //    时间容忍窗口 (毫秒)
    private static final long TIME_TOLERANCE = 60000;

    private AtomicInteger currentGlobalRate = new AtomicInteger(0);

    @Autowired
    private ReactiveRedisTemplate<String, String> reactiveRedisTemplate;
    @Autowired
    private SM2Util sm2Util;
    @Autowired
    private ReplayAttackPreventer replayPreventer;
    @Autowired
    private SessionServiceImpl sessionService;

    // 专用线程池用于阻塞操作
    private final Scheduler decryptScheduler = Schedulers.newBoundedElastic(
            16,
            1000,
            "sm2-decrypt"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return checkRateLimit(exchange)
                .flatMap(allow -> allow ? processAuth(exchange, chain) :
                        respond(exchange, HttpStatus.TOO_MANY_REQUESTS))
                .onErrorResume(e -> handleError(exchange, e));
    }

    private Mono<Boolean> validateSignature(String token, String timestamp,
                                            String random, String secretKey, String sign) {
        return Mono.fromCallable(() -> {
            String serverSign = md5Utils.md5(
                    "token=" + token +
                            "&timestamp=" + timestamp +
                            "&random=" + random +
                            "&secretkey=" + secretKey);
            sessionService.recordUserLogin(secretKey,token);
            return MessageDigest.isEqual(serverSign.getBytes(), sign.getBytes());
        }).onErrorReturn(false);
    }

    /**
     * 响应式验证token有效性
     * @param token 客户端令牌
     * @return 包含secretKey的Mono，如果验证失败返回Mono.error
     */
    private Mono<String> validateToken(String token) {
        log.info("validate token = {}",token);
        return Mono.fromCallable(() -> replayPreventer.getClinetLoginToken(token))
                .subscribeOn(Schedulers.boundedElastic()) // 阻塞操作切换到线程池
                .flatMap(loginToken -> {
                    if (loginToken == null || loginToken.isEmpty()) {
                        log.warn("Invalid or empty token: {}", token);
                        return Mono.error(new ResponseStatusException(
                                HttpStatus.UNAUTHORIZED, "Invalid token"));
                    }
                    return Mono.just(loginToken.replace("\"", ""));
                })
                .timeout(Duration.ofMillis(500)) // 超时控制
                .onErrorResume(e -> {
                    log.error("Token validation failed", e);
                    return Mono.error(new ResponseStatusException(
                            HttpStatus.INTERNAL_SERVER_ERROR, "Token validation error"));
                });
    }

    private Mono<Boolean> validateTimestamp(String timestampStr) {
        return Mono.fromCallable(() -> {
            long timestamp = Long.parseLong(timestampStr);
            long currentTime = System.currentTimeMillis();
            return Math.abs(currentTime - timestamp) <= TIME_TOLERANCE;
        }).onErrorReturn(false);
    }

    // 响应式限流检查
    // 定时重置任务
    private final Scheduler resetScheduler = Schedulers.newSingle("rate-reset");

    @PostConstruct
    public void init() {
        try {
            privateKey = sm2Util.restorePrivateKey(priKey);
            publicKey = sm2Util.restorePublicKey(pubKey);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        // 每分钟整点时刻重置计数器
        resetScheduler.schedulePeriodically(
                () -> {
                    int oldValue = currentGlobalRate.getAndSet(0);
                    if (oldValue > 0) {
                        log.debug("Reset global rate counter: {}", oldValue);
                    }
                },
                calculateInitialDelay(), // 计算到下一分钟整点的延迟
                60, // 每分钟执行一次
                TimeUnit.SECONDS
        );
    }

    private long calculateInitialDelay() {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime nextMinute = now.truncatedTo(ChronoUnit.MINUTES)
                .plusMinutes(1);
        return Duration.between(now, nextMinute).getSeconds();
    }

    private Mono<Boolean> checkRateLimit(ServerWebExchange exchange) {
        return Mono.fromCallable(() -> {
            int current = currentGlobalRate.incrementAndGet();
            boolean allowed = current <= globalRateLimit;
            log.info("check rate limit");
            if (!allowed) {
                log.warn("Global rate limit exceeded: {}/{}",
                        current, globalRateLimit);
                exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
            }
            return allowed;
        }).subscribeOn(Schedulers.boundedElastic());
    }

    private Mono<Boolean> checkGlobalRate() {
        return reactiveRedisTemplate.opsForValue().increment("rate:global")
                .flatMap(count -> reactiveRedisTemplate.expire("rate:global", Duration.ofMinutes(1))
                        .thenReturn(count <= globalRateLimit));
    }

    // 认证主流程
    private Mono<Void> processAuth(ServerWebExchange exchange, GatewayFilterChain chain) {
        log.info("processAuth");
        return Mono.just(exchange)
                .filterWhen(e -> Mono.just(!isLoginRequest(e))) // 登录请求跳过
                .flatMap(e -> validateRequest(e).flatMap(valid ->
                                valid ? decryptAndForward(e, chain) :
                                        respond(e, HttpStatus.UNAUTHORIZED))
                        .switchIfEmpty(chain.filter(exchange))); // 登录请求直接放行
    }

    // 请求头验证
    private Mono<Boolean> validateRequest(ServerWebExchange exchange) {
        return Mono.zip(
                getRequiredHeader(exchange, "token"),
                getRequiredHeader(exchange, "timestamp"),
                getRequiredHeader(exchange, "random"),
                getRequiredHeader(exchange, "sign")
        ).flatMap(tuple -> {
            String token = tuple.getT1();
            String timestamp = tuple.getT2();
            String random = tuple.getT3();
            String sign = tuple.getT4();
            log.info("validate request token = {}",token);
            return validateToken(token)
                    .flatMap(loginToken -> Mono.zip(
                            validateTimestamp(timestamp),
                            validateSignature(token, timestamp, random, loginToken, sign),
                            validateNonce(random, timestamp)
                    )).map(results -> results.getT1() && results.getT2() && results.getT3());
        });
    }

    // 响应式Nonce验证
    private Mono<Boolean> validateNonce(String random, String timestamp) {
        String redisKey = NONCE_USED_KEY_PREFIX + random + timestamp;
        return reactiveRedisTemplate.opsForValue().setIfAbsent(
                        redisKey, "1", Duration.ofMillis(TIME_TOLERANCE))
                .defaultIfEmpty(false)
                .onErrorReturn(false);
    }

    private String detectContentType(byte[] data) {
        if (data == null || data.length == 0) return "unknown";

        // 检查JSON特征
        if (isLikelyJson(data)) return "json";

        // 检查XML特征
        if (data.length > 5 && new String(data, 0, 5).equals("<?xml")) {
            return "xml";
        }

        // 检查常见二进制文件特征
        if (data.length > 4) {
            // PNG文件
            if (data[0] == (byte) 0x89 && data[1] == 'P' &&
                    data[2] == 'N' && data[3] == 'G') {
                return "image/png";
            }
            // PDF文件
            if (data[0] == '%' && data[1] == 'P' &&
                    data[2] == 'D' && data[3] == 'F') {
                return "application/pdf";
            }
        }

        // 默认认为是二进制数据
        return "binary";
    }

    // 请求体解密转发
    private Mono<Void> decryptAndForward(ServerWebExchange exchange, GatewayFilterChain chain) {
        return DataBufferUtils.join(exchange.getRequest().getBody())
                .flatMap(dataBuffer -> {
                    try {
                        byte[] bytes = new byte[dataBuffer.readableByteCount()];
                        dataBuffer.read(bytes);
                        DataBufferUtils.release(dataBuffer);

                        // 1. 判断是否为二进制数据（不处理）
                        String contentType = detectContentType(bytes);
                        if (!"json".equals(contentType)) {
                            log.debug("Binary content detected, size={} bytes", bytes.length);
                            // 显式重建二进制请求体
                            ServerHttpRequestDecorator decorator = new ServerHttpRequestDecorator(exchange.getRequest()) {
                                @Override
                                public Flux<DataBuffer> getBody() {
                                    return Flux.just(exchange.getResponse().bufferFactory().wrap(bytes));
                                }
                            };
                            return chain.filter(exchange.mutate().request(decorator).build());
                        }

                        // 2. 尝试解析JSON并解密param字段
                        return processJsonContent(bytes)
                                .flatMap(processedBody -> {
                                    // 3. 构建装饰后的请求
                                    ServerHttpRequestDecorator decorator = new ServerHttpRequestDecorator(exchange.getRequest()) {
                                        @Override
                                        public Flux<DataBuffer> getBody() {
                                            log.info("process json content res body = {}",processedBody);
                                            return Flux.just(exchange.getResponse()
                                                    .bufferFactory()
                                                    .wrap(processedBody.getBytes(StandardCharsets.UTF_8)));
                                        }

                                        @Override
                                        public HttpHeaders getHeaders() {
                                            HttpHeaders headers = new HttpHeaders();
                                            headers.putAll(super.getHeaders());
                                            headers.setContentLength(processedBody.length());
                                            return headers;
                                        }
                                    };
                                    return chain.filter(exchange.mutate().request(decorator).build());
                                });
                    } catch (Exception e) {
                        log.error("Request body processing failed", e);
                        exchange.getResponse().setStatusCode(HttpStatus.BAD_REQUEST);
                        return exchange.getResponse().setComplete();
                    }
                });
    }

    /**
     * 判断是否为二进制数据
     */
    private boolean isBinaryData(byte[] data) {
        if (data == null || data.length == 0) return false;

        // 检查常见二进制文件魔数
        if (data.length > 4) {
            // PNG
            if (data[0] == (byte) 0x89 && data[1] == 'P' &&
                    data[2] == 'N' && data[3] == 'G') return true;
            // JPEG
            if (data[0] == (byte) 0xFF && data[1] == (byte) 0xD8) return true;
            // PDF
            if (data[0] == '%' && data[1] == 'P' &&
                    data[2] == 'D' && data[3] == 'F') return true;
        }

        // 检查非文本特征（ASCII控制字符）
        int checkLength = Math.min(data.length, 512);
        for (int i = 0; i < checkLength; i++) {
            if ((data[i] & 0xFF) < 0x20 &&
                    data[i] != '\t' && data[i] != '\n' && data[i] != '\r') {
                return true;
            }
        }
        return false;
    }

    /**
     * 处理JSON内容并解密param字段
     */
    private Mono<String> processJsonContent(byte[] requestBody) {
        return Mono.fromCallable(() -> {
                    String bodyStr = new String(requestBody, StandardCharsets.UTF_8);

                    // 快速JSON格式检查
                    if (!bodyStr.trim().startsWith("{") || !bodyStr.trim().endsWith("}")) {
                        return bodyStr; // 非JSON格式直接返回
                    }

                    try {
                        JSONObject json = JSON.parseObject(bodyStr);
                        if (json.containsKey("param")) {
                            String encrypted = json.getString("param");
                            String decrypted = sm2Util.decrypt(encrypted, privateKey);
                            log.info("procssJsonContent param = {},decrypt = {}",encrypted,decrypted);
//                            json.put("param", decrypted);
                            return decrypted;
                        }
                        return bodyStr;
                    } catch (Exception e) {
                        log.warn("JSON processing failed, return original content", e);
                        return bodyStr; // 解析失败返回原始内容
                    }
                })
                .subscribeOn(Schedulers.boundedElastic())
                .timeout(Duration.ofMillis(500));
    }

    /**
     * 判断是否为二进制内容
     */
    private boolean isBinaryContent(byte[] data) {
        if (data == null || data.length == 0) return false;

        // 检查常见二进制文件魔数
        if (data.length > 4) {
            // PNG
            if (data[0] == (byte) 0x89 && data[1] == 'P' &&
                    data[2] == 'N' && data[3] == 'G') {
                return true;
            }
            // JPEG
            if (data[0] == (byte) 0xFF && data[1] == (byte) 0xD8) {
                return true;
            }
            // PDF
            if (data[0] == '%' && data[1] == 'P' &&
                    data[2] == 'D' && data[3] == 'F') {
                return true;
            }
            // GIF
            if (data[0] == 'G' && data[1] == 'I' &&
                    data[2] == 'F' && data[3] == '8') {
                return true;
            }
        }

        // 检查是否为非文本内容（根据内容特征）
        int textThreshold = Math.min(data.length, 512);
        for (int i = 0; i < textThreshold; i++) {
            if ((data[i] & 0xFF) < 0x20 && data[i] != '\t' &&
                    data[i] != '\n' && data[i] != '\r') {
                return true; // 发现控制字符（非文本特征）
            }
        }

        return false;
    }

    /**
     * 解密处理（仅处理JSON）
     */
    private Mono<String> decryptBody(byte[] encrypted) {
        return Mono.fromCallable(() -> {
                    String content = new String(encrypted, StandardCharsets.UTF_8);

                    // 验证是否为JSON
                    if (!isLikelyJson(content.getBytes())) {
                        log.debug("Non-JSON content, skip decryption");
                        return content; // 返回原始内容
                    }

                    // 尝试解析JSON
                    try {
                        JSONObject json = JSON.parseObject(content);
                        if (json.containsKey("param")) {
                            return sm2Util.decrypt(json.getString("param"), privateKey);
                        }
                        return content;
                    } catch (Exception e) {
                        log.warn("JSON parsing failed, skip decryption", e);
                        return content;
                    }
                })
                .subscribeOn(Schedulers.boundedElastic())
                .timeout(Duration.ofMillis(500))
                .onErrorResume(e -> {
                    log.error("Decryption failed", e);
                    return Mono.error(new ResponseStatusException(
                            HttpStatus.BAD_REQUEST, "Request body processing failed"));
                });
    }

    /**
     * 简单JSON格式检测
     */
    private boolean isLikelyJson(byte[] data) {
        if (data == null || data.length == 0) return false;

        // 检查前几个字节是否是JSON起始字符
        // 修复拼写错误
        int firstNonWhitespace = 0;
        while (firstNonWhitespace < data.length &&
                Character.isWhitespace(data[firstNonWhitespace])) {
            firstNonWhitespace++;
        }

        if (firstNonWhitespace >= data.length) return false;

        byte firstChar = data[firstNonWhitespace];
        if (firstChar != '{' && firstChar != '[') return false;

        // 检查最后一个非空白字符是否是JSON结束字符
        int lastNonWhitespace = data.length - 1;
        while (lastNonWhitespace >= 0 &&
                Character.isWhitespace(data[lastNonWhitespace])) {
            lastNonWhitespace--;
        }

        if (lastNonWhitespace < 0) return false;

        byte lastChar = data[lastNonWhitespace];
        return (firstChar == '{' && lastChar == '}') ||
                (firstChar == '[' && lastChar == ']');
    }


    // 错误处理
    private Mono<Void> handleError(ServerWebExchange exchange, Throwable e) {
        HttpStatus status = e instanceof ResponseStatusException ?
                ((ResponseStatusException)e).getStatus() :
                HttpStatus.INTERNAL_SERVER_ERROR;
        return respond(exchange, status);
    }

    private Mono<Void> respond(ServerWebExchange exchange, HttpStatus status) {
        exchange.getResponse().setStatusCode(status);
        return exchange.getResponse().setComplete();
    }

    // 其他辅助方法...
    private Mono<String> getRequiredHeader(ServerWebExchange exchange, String name) {
        return Mono.justOrEmpty(exchange.getRequest().getHeaders().getFirst(name))
                .switchIfEmpty(Mono.error(new ResponseStatusException(
                        HttpStatus.BAD_REQUEST, "Missing header: " + name)));
    }

    private boolean isLoginRequest(ServerWebExchange exchange) {
        String path = exchange.getRequest().getPath().toString();
        return path.contains("/login") &&
                HttpMethod.POST.equals(exchange.getRequest().getMethod());
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}