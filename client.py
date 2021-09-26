import socket, transmit
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from Crypto.Cipher import AES


# Create a UDP socket at client side
serverAddressPort = ("127.0.0.1", 20002)
bufferSize = 64
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def handshake():
    client_private_key = ec.generate_private_key(
        ec.SECP384R1, default_backend())
    client_public_key = client_private_key.public_key()

    # Convert to bytes in order to transfer
    # X962 encodes for elliptic curve and compresses with CompressedPoint
    encoded_client_public_key = client_public_key.public_bytes(
        Encoding.X962, PublicFormat.CompressedPoint
    )

    print("\nReceived server public key \U0001F511 \U00002B05")
    server_public_key, _ = client_socket.recvfrom(bufferSize)

    print("\nSend Client public key to Server \U0001F511 \U000027A1")
    client_socket.sendto(encoded_client_public_key, serverAddressPort)

    print("\nCumputing shared key... \U0001F9EE")
    shared_key = client_private_key.exchange(
        ec.ECDH(),
        ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP384R1(), server_public_key),
    )

    print("\nDeriving key...")
    # perform key derivation
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

    print("\nHandshake done. \U0001F91D")

    return derived_key


def init_session():

    print("Initializing client... \U0001F64B")
    print("Client ready! \U00002705")

    bytesToSend = str.encode("Wanna play? \U0001F939")
    # Send to server using created UDP socket
    client_socket.sendto(bytesToSend, serverAddressPort)
    print(f"\nSent to Server:{bytesToSend.decode()}")

    derivedKey = handshake()

    while True:
        transmit.send(input("\nMessage to server \U0001F50F: ").encode(),
                      derivedKey, serverAddressPort[0], serverAddressPort[1], client_socket)
        print("Sent!")
init_session()
