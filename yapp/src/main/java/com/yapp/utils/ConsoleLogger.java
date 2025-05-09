package com.yapp.utils;

public class ConsoleLogger implements Logger{
    public void log(String message) {
        System.err.println(message);
    }
}
