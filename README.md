

```
yapp
├─ logs
│  ├─ securechat-server.2025-05-15.log.gz
│  └─ securechat-server.log
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
   │  │  │        │  ├─ libsignal
   │  │  │        │  │  ├─ EncryptedMessageResult.java
   │  │  │        │  │  ├─ PreKeyBundleBuilder.java
   │  │  │        │  │  ├─ PreKeyBundleDTO.java
   │  │  │        │  │  ├─ SignalKeyStore.java
   │  │  │        │  │  └─ SignalProtocolManager.java
   │  │  │        │  └─ RSAEncryptor.java
   │  │  │        ├─ gui
   │  │  │        │  └─ ChatWindow.java
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
   │  │  │        │  ├─ MessageType.java
   │  │  │        │  ├─ Packet.java
   │  │  │        │  └─ PacketType.java
   │  │  │        ├─ server
   │  │  │        │  ├─ ClientManager.java
   │  │  │        │  └─ Server.java
   │  │  │        ├─ store
   │  │  │        │  ├─ FilePreKeyStore.java
   │  │  │        │  ├─ InMemoryPreKeyStore.java
   │  │  │        │  └─ PreKeyStore.java
   │  │  │        └─ utils
   │  │  └─ resources
   │  │     ├─ config.properties
   │  │     └─ logback.xml
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
      │  │     │  ├─ libsignal
      │  │     │  │  ├─ EncryptedMessageResult.class
      │  │     │  │  ├─ PreKeyBundleBuilder.class
      │  │     │  │  ├─ PreKeyBundleDTO.class
      │  │     │  │  ├─ SignalKeyStore.class
      │  │     │  │  └─ SignalProtocolManager.class
      │  │     │  └─ RSAEncryptor.class
      │  │     ├─ gui
      │  │     │  └─ ChatWindow.class
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
      │  │     │  ├─ MessageType.class
      │  │     │  ├─ Packet.class
      │  │     │  └─ PacketType.class
      │  │     ├─ server
      │  │     │  ├─ ClientManager.class
      │  │     │  └─ Server.class
      │  │     ├─ store
      │  │     │  ├─ FilePreKeyStore.class
      │  │     │  ├─ InMemoryPreKeyStore.class
      │  │     │  └─ PreKeyStore.class
      │  │     └─ utils
      │  ├─ config.properties
      │  └─ logback.xml
      ├─ generated-sources
      │  └─ annotations
      ├─ maven-status
      │  └─ maven-compiler-plugin
      │     └─ compile
      │        └─ default-compile
      │           ├─ createdFiles.lst
      │           └─ inputFiles.lst
      └─ test-classes

```