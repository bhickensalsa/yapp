package com.securechat.gui;

import javax.swing.*;

public class ChatWindow {
    public static void show() {
        JFrame frame = new JFrame("Secure Chat");
        frame.setSize(400, 600);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setVisible(true);
    }
}
