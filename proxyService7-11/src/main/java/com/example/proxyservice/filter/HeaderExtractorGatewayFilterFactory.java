package com.example.proxyservice.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

@Component
public class HeaderExtractorGatewayFilterFactory extends
        AbstractGatewayFilterFactory<HeaderExtractorGatewayFilterFactory.Config> {

    public HeaderExtractorGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            // 1. 获取指定Header
            String nonce = request.getHeaders().getFirst("X-Nonce");
            String keyPasswd = request.getHeaders().getFirst("keyPasswd");

            // 2. 将Header放入请求属性中(可选)
            exchange.getAttributes().put("NONCE_HEADER", nonce);

            return chain.filter(exchange);
        };
    }

    public static class Config {
        // 可添加配置参数
    }
}
