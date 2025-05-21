
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
   │  │  │        │  └─ libsignal
   │  │  │        │     ├─ PreKeyBundleBuilder.java
   │  │  │        │     ├─ SessionManager.java
   │  │  │        │     └─ SignalProtocolManager.java
   │  │  │        ├─ Launcher.java
   │  │  │        ├─ model
   │  │  │        │  ├─ KeyBundle.java
   │  │  │        │  └─ UserProfile.java
   │  │  │        ├─ network
   │  │  │        │  ├─ DecryptedMessageListener.java
   │  │  │        │  ├─ MessageRouter.java
   │  │  │        │  ├─ PacketManager.java
   │  │  │        │  ├─ PeerConnection.java
   │  │  │        │  └─ UserStatusUpdateListener.java
   │  │  │        ├─ protocol
   │  │  │        │  ├─ dto
   │  │  │        │  │  ├─ PreKeyBundleDTO.java
   │  │  │        │  │  ├─ UserInfoDTO.java
   │  │  │        │  │  └─ UserListUpdateDTO.java
   │  │  │        │  ├─ Packet.java
   │  │  │        │  └─ PacketType.java
   │  │  │        ├─ server
   │  │  │        │  ├─ ClientManager.java
   │  │  │        │  ├─ ConnectionListener.java
   │  │  │        │  └─ Server.java
   │  │  │        ├─ store
   │  │  │        │  └─ SignalStore.java
   │  │  │        └─ ui
   │  │  │           └─ ClientControlUI.java
   │  │  └─ resources
   │  │     ├─ config.properties
   │  │     ├─ logback.xml
   │  │     └─ styles.css
   │  └─ test
   │     └─ java
   └─ target
      ├─ classes
      │  ├─ com
      │  │  └─ securechat
      │  │     ├─ client
      │  │     │  ├─ UserClient$IncomingMessageListener.class
      │  │     │  └─ UserClient.class
      │  │     ├─ config
      │  │     │  └─ ConfigLoader.class
      │  │     ├─ crypto
      │  │     │  └─ libsignal
      │  │     │     ├─ PreKeyBundleBuilder.class
      │  │     │     ├─ SessionManager.class
      │  │     │     └─ SignalProtocolManager.class
      │  │     ├─ Launcher.class
      │  │     ├─ model
      │  │     │  ├─ KeyBundle.class
      │  │     │  └─ UserProfile.class
      │  │     ├─ network
      │  │     │  ├─ DecryptedMessageListener.class
      │  │     │  ├─ MessageRouter.class
      │  │     │  ├─ PacketManager$1.class
      │  │     │  ├─ PacketManager.class
      │  │     │  ├─ PeerConnection.class
      │  │     │  └─ UserStatusUpdateListener.class
      │  │     ├─ protocol
      │  │     │  ├─ dto
      │  │     │  │  ├─ PreKeyBundleDTO.class
      │  │     │  │  ├─ UserInfoDTO.class
      │  │     │  │  └─ UserListUpdateDTO.class
      │  │     │  ├─ Packet.class
      │  │     │  └─ PacketType.class
      │  │     ├─ server
      │  │     │  ├─ ClientManager.class
      │  │     │  ├─ ConnectionListener.class
      │  │     │  ├─ Server$1.class
      │  │     │  └─ Server.class
      │  │     ├─ store
      │  │     │  └─ SignalStore.class
      │  │     └─ ui
      │  │        └─ ClientControlUI.class
      │  ├─ config.properties
      │  ├─ logback.xml
      │  └─ styles.css
      ├─ generated-sources
      │  └─ annotations
      └─ maven-status
         └─ maven-compiler-plugin
            └─ compile
               └─ default-compile
                  ├─ createdFiles.lst
                  └─ inputFiles.lst

```