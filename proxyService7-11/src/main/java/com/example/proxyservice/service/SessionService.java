package com.example.proxyservice.service;

import reactor.core.publisher.Mono;

public interface SessionService {
    /**
     * 记录用户登录信息（事务安全）
     *
     * @param token 登陆token
     * @return
     */
    public void recordUserLogin(String clientLoginToken, String token);


    /**
     * 更新最后活跃时间 - 使用stringRedisTemplate
     *
     * @return
     */
    public Mono<Void> updateActivity(String token);

    /**
     * 处理用户登出 - 混合使用两种Template
     *
     * @return
     */
    public Mono<Void> handleLogout();

    /**
     * 定时清理过期会话 - 主要使用stringRedisTemplate
     *
     * @return
     */
    public void cleanExpiredSessions();

    Mono<Boolean> validateSession(String token);

    Mono<String> getClientLoginToken(String sessionToken);
}
