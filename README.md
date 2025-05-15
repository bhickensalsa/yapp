
```
yapp
├─ README.md
└─ yapp
   ├─ pom.xml
   ├─ src
   │  ├─ main
   │  │  ├─ java
   │  │  │  └─ com
   │  │  │     └─ securechat
   │  │  │        ├─ client
   │  │  │        │  └─ UserClient.java
   │  │  │        ├─ config
   │  │  │        │  └─ ConfigLoader.java
   │  │  │        ├─ crypto
   │  │  │        │  ├─ EncryptionManager.java
   │  │  │        │  ├─ Encryptor.java
   │  │  │        │  ├─ KeyManager.java
   │  │  │        │  └─ libsignal
   │  │  │        │     ├─ PreKeyBundleBuilder.java
   │  │  │        │     ├─ SignalKeyStore.java
   │  │  │        │     └─ SignalProtocolManager.java
   │  │  │        ├─ gui
   │  │  │        ├─ Launcher.java
   │  │  │        ├─ model
   │  │  │        │  ├─ KeyBundle.java
   │  │  │        │  └─ UserProfile.java
   │  │  │        ├─ network
   │  │  │        │  ├─ MessageRouter.java
   │  │  │        │  └─ PeerConnection.java
   │  │  │        ├─ protocol
   │  │  │        │  ├─ Message.java
   │  │  │        │  ├─ MessageSerializer.java
   │  │  │        │  └─ MessageType.java
   │  │  │        ├─ server
   │  │  │        │  ├─ ClientManager.java
   │  │  │        │  └─ Server.java
   │  │  │        └─ utils
   │  │  │           ├─ ConsoleLogger.java
   │  │  │           └─ Logger.java
   │  │  └─ resources
   │  │     └─ config.properties
   │  └─ test
   │     └─ java
   └─ target
      ├─ classes
      │  ├─ com
      │  │  └─ securechat
      │  │     ├─ client
      │  │     │  └─ UserClient.class
      │  │     ├─ config
      │  │     │  └─ ConfigLoader.class
      │  │     ├─ crypto
      │  │     │  ├─ EncryptionManager.class
      │  │     │  ├─ Encryptor.class
      │  │     │  ├─ KeyManager.class
      │  │     │  └─ libsignal
      │  │     │     ├─ PreKeyBundleBuilder.class
      │  │     │     ├─ SignalKeyStore.class
      │  │     │     └─ SignalProtocolManager.class
      │  │     ├─ gui
      │  │     ├─ Launcher.class
      │  │     ├─ model
      │  │     │  ├─ KeyBundle.class
      │  │     │  └─ UserProfile.class
      │  │     ├─ network
      │  │     │  ├─ MessageRouter.class
      │  │     │  └─ PeerConnection.class
      │  │     ├─ protocol
      │  │     │  ├─ Message.class
      │  │     │  ├─ MessageSerializer.class
      │  │     │  └─ MessageType.class
      │  │     ├─ server
      │  │     │  ├─ ClientManager.class
      │  │     │  └─ Server.class
      │  │     └─ utils
      │  │        ├─ ConsoleLogger.class
      │  │        └─ Logger.class
      │  └─ config.properties
      └─ test-classes

```