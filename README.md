# RatchetedKeyExchangeInstantiation
Instantiation of [ratcheted key exchange](https://github.com/RUB-NDS/RatchetedKeyExchange) ([Poettering and Rösler, CRYPTO 2018](https://eprint.iacr.org/2018/296.pdf)) by Marco Smeets

## Algorithm Choice
We chose the following algorithms for our implementation:

* KEM:
* MAC:
* Hash:
* HIBE:
* Signature:

## Build Instructions
### Prerequisites
- Currently, the project is only buildable on Linux 64Bit.
- Make sure to have **CMake** installed.
- ${JAVA_HOME} environment variable is set to a base directory of a Java installation so that Maven can find the jni header files.
### Building
If everything is set up properly, the standard maven commands should work to compile and test the project.
 
You can compile the project by calling
`mvn compile`
and run the Unit tests by calling
`mvn test`.
