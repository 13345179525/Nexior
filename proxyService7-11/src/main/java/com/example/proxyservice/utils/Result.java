package com.example.proxyservice.utils;


public class Result {

    public Result(String token, String message, int code) {
        this.token = token;
        this.message = message;
        this.code = code;
    }

    @Override
    public String toString() {
        return "{" +
                "\"token\":\"" + token + "\"," +
                "\"message\":\"" + message + "\"," +
                "\"code\":" + code +
                "}";
    }

    private final String token;
    private final String message;
    private final int code;


}