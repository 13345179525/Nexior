package com.example.proxyservice.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SafeCorsFilter implements GlobalFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 1. 在响应提交前设置CORS头
        ServerHttpResponse response = exchange.getResponse();
        response.beforeCommit(() -> {
            HttpHeaders headers = response.getHeaders();
            headers.setAccessControlAllowOrigin("http://172.16.0.202:31004");
            headers.setAccessControlAllowMethods(Arrays.asList(
                    HttpMethod.GET, HttpMethod.POST, HttpMethod.OPTIONS));
            headers.setAccessControlMaxAge(3600L);
            return Mono.empty();
        });

        // 2. 特殊处理OPTIONS请求
        if (exchange.getRequest().getMethod() == HttpMethod.OPTIONS) {
            response.setStatusCode(HttpStatus.NO_CONTENT);
            return response.setComplete();
        }

        // 3. 继续过滤器链
        return chain.filter(exchange);
    }
}