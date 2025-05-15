package com.securechat.utils;

public class ConsoleLogger implements Logger {
    @Override
    public void info(String message) {
        System.out.println("[INFO] " + message);
    }

    @Override
    public void error(String message) {
        System.err.println("[ERROR] " + message);
    }
}
