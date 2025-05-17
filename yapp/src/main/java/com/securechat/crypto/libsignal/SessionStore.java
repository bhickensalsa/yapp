package com.securechat.crypto.libsignal;

import java.util.List;

import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.SessionRecord;

public interface SessionStore {
    boolean containsSession(SignalProtocolAddress address);
    SessionRecord loadSession(SignalProtocolAddress address);
    List<Integer> getSubDeviceSessions(String name);
    void storeSession(SignalProtocolAddress address, SessionRecord record);
    void deleteSession(SignalProtocolAddress address);
    void deleteAllSessions(String name);
}
