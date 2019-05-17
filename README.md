# Ratcheted Key Exchange
Implementation of ratcheted key exchange protocol ([Poettering and Rösler, CRYPTO 2018](https://eprint.iacr.org/2018/296.pdf)) by Marco Smeets

## Build Instructions
### Prerequisites
- Currently, the project is only buildable on Linux 64Bit.
- Make sure to have **CMake** installed.
- ${JAVA_HOME} environment variable is set to a base directory of a Java installation so that Maven can find the jni header files.
### Building
If everything is set up properly, the standard maven commands should work to compile and test the project.
 
You can compile and install the project by calling
`mvn install`
and run the Unit tests by calling
`mvn test`.

## Important Note
This code is aimed to be an accessible proof of concept implementation. Please do not use it in production as there might be implementation bugs (affecting security).
