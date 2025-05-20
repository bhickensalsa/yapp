
```
yapp
├─ logs
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
   │  │  │        │  └─ libsignal
   │  │  │        │     ├─ PreKeyBundleBuilder.java
   │  │  │        │     ├─ PreKeyBundleDTO.java
   │  │  │        │     ├─ SessionManager.java
   │  │  │        │     └─ SignalProtocolManager.java
   │  │  │        ├─ gui
   │  │  │        │  └─ ChatWindow.java
   │  │  │        ├─ Launcher.java
   │  │  │        ├─ model
   │  │  │        │  ├─ KeyBundle.java
   │  │  │        │  └─ UserProfile.java
   │  │  │        ├─ network
   │  │  │        │  ├─ MessageRouter.java
   │  │  │        │  ├─ PacketManager.java
   │  │  │        │  └─ PeerConnection.java
   │  │  │        ├─ protocol
   │  │  │        │  ├─ Packet.java
   │  │  │        │  └─ PacketType.java
   │  │  │        ├─ server
   │  │  │        │  ├─ ClientManager.java
   │  │  │        │  └─ Server.java
   │  │  │        └─ store
   │  │  │           └─ SignalStore.java
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
      │  │     │  └─ libsignal
      │  │     │     ├─ PreKeyBundleBuilder.class
      │  │     │     ├─ PreKeyBundleDTO.class
      │  │     │     ├─ SessionManager.class
      │  │     │     └─ SignalProtocolManager.class
      │  │     ├─ gui
      │  │     │  └─ ChatWindow.class
      │  │     ├─ Launcher.class
      │  │     ├─ model
      │  │     │  ├─ KeyBundle.class
      │  │     │  └─ UserProfile.class
      │  │     ├─ network
      │  │     │  ├─ MessageRouter.class
      │  │     │  ├─ PacketManager$1.class
      │  │     │  ├─ PacketManager.class
      │  │     │  └─ PeerConnection.class
      │  │     ├─ protocol
      │  │     │  ├─ Packet.class
      │  │     │  └─ PacketType.class
      │  │     ├─ server
      │  │     │  ├─ ClientManager.class
      │  │     │  ├─ Server$1.class
      │  │     │  └─ Server.class
      │  │     └─ store
      │  │        └─ SignalStore.class
      │  ├─ config.properties
      │  └─ logback.xml
      ├─ generated-sources
      │  └─ annotations
      └─ maven-status
         └─ maven-compiler-plugin
            └─ compile
               └─ default-compile
                  ├─ createdFiles.lst
                  └─ inputFiles.lst

```