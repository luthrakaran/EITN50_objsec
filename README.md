# Object Security

A proof-of-concept demonstration of a simple handshake with Elliptic Curve Diffie-Hellman.

## Description

This demo simulates an IoT connection between client and server using UDP with a maximum packet size of 64 bytes.
Ephemeral Diffie-Hellman Key Exchange handshake is established using an elliptic curve.
AES is used to encrypt data sent over an unencrypted channel.

## Getting Started

### Dependencies

* PyCrypto
* Cryptography 

### Installing

* Run requirements.txt to install dependencies

### Executing program

* First run server.py to initialize server
* Run client.py to initiate key exchange and establish a connection
* Send data to server
* Close connection with "Bye!"
```
python3 server.py
```
Open a new terminal and enter the command:
```
python3 client.py
```
This will initiate the handshake.


## Author

Karan Luthra _luthrakaran@gmail.com_

