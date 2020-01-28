# Java-Cryptography-Best-Practices

As *cybersecurity* gets more relevent every day and examples of *secure Implementations* are often hard to come by -  
this Repo aims to get some Best-Practice-Implementations of common and secure Cryptography Algorithms in Java out there.

Only well-known / secure Libraries or the Standard-Libraries are used.  
I aim to choose secure Paremters for the Cryptographic Functions and also explain them in the comments.

Currently the following Crypto-Algo-Implementations are finished and to my best knowledge secure to use:

## Asymmetric-Encryption:
* RSAAsymmetricEncryption.java using "RSA-4096 with OAEP-SHA512MGF1Padding"
## Secure Hash-Functions
* Argon2iHashSecure using Argon2i and explaining all parameters
## General Hash-Functions
* SHA512Hash
* SHA256Hash

### As you may have noticed this repo is work in Progress.
### Several more Implementation will come next month
