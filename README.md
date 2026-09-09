# TNM031 - Network Programming and Security

This repository is for my implementations of Labs 2 and 3 in the course **Network Programming and Security (TNM031)** at Linköping University (LiU).

Lab 1 covers theory questions based on network traffic inspected with Wireshark and is not included here. Lab 4 is a mini-project that will have its own repository.

## Lab 2 - RSA in Java

Lab 2 requires an implementation of RSA in Java. The program generates a public/private key pair, encrypts a text message, decrypts it, and checks whether the recovered text matches the original.

### Requirements

A Java Development Kit (JDK) with both `javac` and `java` available in your terminal. The project has been verified with **Eclipse Temurin JDK 21.0.9** and uses only Java's standard library.

### Build and run

After cloning the repository, open a terminal in the repository root and run:

```powershell
cd Lab2
javac Main.java RSA.java KeyPair.java Key.java
java Main
```

The program prints the original message, the encrypted number, and the recovered message. The supplied example should finish with:

```text
The original and recovered messages are the same: true
```

Each run generates new keys, so the encrypted number changes. To try another message, edit the `message` string in [`Lab2/Main.java`](Lab2/Main.java), then recompile and run from the `Lab2` directory.

### Current status

The demonstration works for the supplied message. The following limitations remain:

- Text reconstruction needs fixes for messages beginning with accented characters or emoji, empty messages, and original leading null characters (`U+0000`).
- Messages must fit in one RSA block. The program rejects messages whose encoded integer is at least the key's modulus.
- This is educational textbook RSA; it does not implement an encryption encoding scheme such as RSA-OAEP.

## Lab 3

Planned; not yet implemented.
