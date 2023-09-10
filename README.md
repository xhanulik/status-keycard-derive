# status-keycard-derive applet

[![Build Status](https://travis-ci.org/crocs-muni/javacard-gradle-template-edu.svg?branch=master)](https://travis-ci.org/crocs-muni/javacard-gradle-template-edu)

## How to use

- Clone this template repository:

```
git clone --recursive status-keycard
```
- Run Gradle wrapper `./gradlew` on Unix-like system or `./gradlew.bat` on Windows
to build the project for the first time (Gradle will be downloaded if not installed).

## Building cap

- Setup your Applet ID (`AID`) in the `./applet/build.gradle`.

- Run the `buildJavaCard` task:

```bash
./gradlew buildJavaCard  --info --rerun-tasks
```

Generates a new cap file `./applet/out/cap/applet.cap`


## Installation on a (physical) card

```bash
./gradlew installJavaCard
```

Or inspect already installed applets:

```bash
./gradlew listJavaCard
```

## APDU 

- CLA: `0xB0`
1. test command:
   - INS: `0x00`
   - P1: `0x00`
   - P2: `0x00`
   - data: none
2. private child key derivation:
   - INS: `0x01`
   - P1: `0x00`
   - P2: `0x00`
   - data: `private key [32B] | public key [65B] | chain code [32B] | derivation path`

## Dependencies

This project uses mainly:

- https://github.com/bertrandmartel/javacard-gradle-plugin
- https://github.com/martinpaljak/ant-javacard
- https://github.com/martinpaljak/oracle_javacard_sdks
- https://github.com/licel/jcardsim
- Petr Svenda scripts 

Kudos for a great work!

### JavaCard support

Thanks to Martin Paljak's [ant-javacard] and [oracle_javacard_sdks] we support:

- JavaCard 2.1.2
- JavaCard 2.2.1
- JavaCard 2.2.2
- JavaCard 3.0.3
- JavaCard 3.0.4
- JavaCard 3.0.5u1
- JavaCard 3.1.0b43

## Supported Java versions

Java 8-u271 is the minimal version supported. 

Make sure you have up to date java version (`-u` version) as older java 8 versions
have problems with recognizing some certificates as valid.

Only some Java versions are supported by the JavaCard SDKs.
Check the following compatibility table for more info: 
https://github.com/martinpaljak/ant-javacard/wiki/Version-compatibility

## Links
[JCardSim]: https://jcardsim.org/
[ant-javacard]: https://github.com/martinpaljak/ant-javacard
[oracle_javacard_sdks]: https://github.com/martinpaljak/oracle_javacard_sdks

