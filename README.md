# eciesjava

[![Build](https://github.com/ecies/java/actions/workflows/gradle.yml/badge.svg)](https://github.com/ecies/java/actions/workflows/gradle.yml)

Elliptic Curve Integrated Encryption Scheme for secp256k1 in Java.

This is the Java version of [eciespy](https://github.com/ecies/py) with a built-in class-like secp256k1 API, you may go there for detailed documentation and learn the mechanism under the hood.

If you want a WASM version to run directly in modern browsers or on some blockchains, check [`ecies-wasm`](https://github.com/ecies/rs-wasm).

## Quick start

```bash
ECKeyPair ecKeyPair = Ecies.generateEcKeyPair();
String encrypted = Ecies.encrypt(ecKeyPair.getPublicHex(true), "MESSAGE_TO_ENCRYPT");
String decrypted = Ecies.decrypt(ecKeyPair.getPrivateHex(), encrypted);
```

## API

```bash
Read Ecies class javadoc
```

## Release Notes

### 0.0.1
- First alpha release