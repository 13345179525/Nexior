package com.example.proxyservice.filter;

import com.example.proxyservice.utils.SM2Util;
import lombok.extern.slf4j.Slf4j;
import org.reactivestreams.Publisher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import javax.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import static jdk.nashorn.internal.runtime.regexp.joni.Config.log;
@Slf4j
@Component
public class ResponseEncryptFilter implements GlobalFilter, Ordered {

    @Value("${security.pubKey}")
    private String pubKey;

    @Autowired
    private SM2Util sm2Util;
    private PublicKey publicKey;

    @PostConstruct
    public void init() {
        try {
            publicKey = sm2Util.restorePublicKey(pubKey);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Failed to initialize public key", e);
        }
    }

    @Override
    public int getOrder() {
        return -1; // 在NettyWriteResponseFilter之前执行
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpResponse originalResponse = exchange.getResponse();
        DataBufferFactory bufferFactory = originalResponse.bufferFactory();

        ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {
            @Override
            public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                if (body instanceof Flux) {
                    return Flux.from(body)
                            .collectList()
                            .flatMap(dataBuffers -> Mono.fromCallable(() -> {
                                        DataBuffer join = bufferFactory.join(dataBuffers);
                                        byte[] content = new byte[join.readableByteCount()];
                                        join.read(content);
                                        DataBufferUtils.release(join);
                                        return content;
                                    })
                                    .subscribeOn(Schedulers.boundedElastic())
                                    .flatMap(content -> {
                                        try {
                                            MediaType contentType = getDelegate().getHeaders().getContentType();

                                            if (shouldEncrypt(contentType, content)) {
                                                // 1. 获取原始响应字符串
                                                String responseStr = new String(content, StandardCharsets.UTF_8);
//                                                log.info("response data = {}",responseStr);
                                                // 2. 执行加密（保持字符串输出）
                                                String encryptedData = sm2Util.encrypt(responseStr, publicKey);
                                                log.debug("Encrypted data string length: {}", encryptedData.length());
//                                                log.info("response encrypt data = {}",encryptedData);
                                                // 3. 转换为字节数组（确保使用UTF-8编码）
                                                byte[] encryptedBytes = encryptedData.getBytes(StandardCharsets.UTF_8);

                                                // 4. 验证长度一致性
                                                if (encryptedBytes.length != encryptedData.length()) {
                                                    log.warn("Length mismatch! String length: {}, Byte length: {}",
                                                            encryptedData.length(), encryptedBytes.length);
                                                }

                                                // 5. 设置响应头
                                                HttpHeaders headers = getDelegate().getHeaders();
                                                headers.setContentLength(encryptedBytes.length); // 使用字节长度

                                                // 6. 写入响应
                                                return super.writeWith(
                                                        Flux.just(bufferFactory.wrap(encryptedBytes))
                                                );
                                            } else {
                                                // 二进制数据保持原样，不修改Content-Length
                                                return super.writeWith(
                                                        Flux.just(bufferFactory.wrap(content))
                                                );
                                            }
                                        } catch (Exception e) {
                                            log.error("Response processing failed", e);
                                            return Mono.error(e);
                                        }
                                    }));
                }
                return super.writeWith(body);
            }

            /**
             * 判断是否需要加密响应内容
             */
            private boolean shouldEncrypt(MediaType contentType, byte[] content) {
                // 1. 根据Content-Type判断
                if (contentType != null) {
//                     不加密二进制类型
                    if (contentType.includes(MediaType.IMAGE_PNG) ||
                            contentType.includes(MediaType.IMAGE_JPEG) ||
                            contentType.includes(MediaType.APPLICATION_PDF) ||
                            contentType.includes(MediaType.APPLICATION_OCTET_STREAM)) {
                        return false;
                    }

                    // 明确需要加密的类型
                    if (contentType.includes(MediaType.APPLICATION_JSON) ||
                            contentType.includes(MediaType.TEXT_PLAIN) ||
                            contentType.includes(MediaType.APPLICATION_XML)) {
                        return true;
                    }
                }

                // 2. 根据内容特征判断
                return !isBinaryContent(content);
            }

            /**
             * 判断是否为二进制内容
             */
            private boolean isBinaryContent(byte[] data) {
                if (data == null || data.length == 0) return false;

                // 检查常见二进制文件特征
                if (data.length > 4) {
                    // PNG文件
                    if (data[0] == (byte) 0x89 && data[1] == 'P' &&
                            data[2] == 'N' && data[3] == 'G') {
                        return true;
                    }
                    // PDF文件
                    if (data[0] == '%' && data[1] == 'P' &&
                            data[2] == 'D' && data[3] == 'F') {
                        return true;
                    }
                    // JPEG文件
                    if (data[0] == (byte) 0xFF && data[1] == (byte) 0xD8) {
                        return true;
                    }
                }

                // 默认认为是文本(需要加密)
                return false;
            }
        };

        return chain.filter(exchange.mutate().response(decoratedResponse).build());
    }
}