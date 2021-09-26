import socket, aes_encryption
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from Crypto.Cipher import AES


localIP = "127.0.0.1"
localPort = 20002
bufferSize = 64

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind((localIP, localPort))


def handshake(client_ip, client_port):

    print("Initializing handshake...\U0001F449")
    server_private_key = ec.generate_private_key(
        ec.SECP384R1, default_backend())
    server_public_key = server_private_key.public_key()

    # Convert to bytes in order to transfer
    # X962 encodes for elliptic curve and compresses with CompressedPoint
    encoded_server_public_key = server_public_key.public_bytes(
        Encoding.X962, PublicFormat.CompressedPoint)

    print("\nPublic key sent to Client \U0001F511 \U000027A1")
    server_socket.sendto(encoded_server_public_key, (client_ip, client_port))

    print("\nPublic key received from Client \U0001F511 \U00002B05")
    client_public_key, _ = server_socket.recvfrom(bufferSize)

    print("\nCumputing shared key... \U0001F9EE")
    shared_key = server_private_key.exchange(ec.ECDH(
    ), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), client_public_key))

    print("\nGenerating derived key...")
    # perform key derivation
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

    print("\nHandshake done. \U0001F91D")
    return derived_key


def init_server():
    print("Initializing server...\U0001F481")
    print("Host up and listening \U0001F442")
    # Listen for incoming datagrams

    bytesAddressPair = server_socket.recvfrom(bufferSize)

    message = bytesAddressPair[0]
    address = bytesAddressPair[1]
    client_ip = address[0]
    client_port = address[1]
    print(f"[Client][{client_ip}:{client_port}]: {message.decode()}")
    derivedKey = handshake(client_ip, client_port)

    while True:
        iv, _ = server_socket.recvfrom(bufferSize)
        encrypted_data, _ = server_socket.recvfrom(bufferSize)
        decrypted_data = aes_encryption.decrypt(encrypted_data, derivedKey, iv)

        if decrypted_data != "Bye!":
            # print data from client
            print(
                f"\nReceived message from Client:\n[{client_ip}:{client_port}] \U0001F50F: {decrypted_data}")
        else:
            print("\nBye Bye \U0001F44B")
            print("\nCtrl-D client.py")
            quit()
init_server()
