
def receive(derived_key):

"""
Function for receiving and decrypting an encrypted message (+ the iv). Returns the decrypted message.
"""


iv, _ = sock.recvfrom(BUFFER_SIZE)
encrypted_message, _ = sock.recvfrom(BUFFER_SIZE)
decrypted_message = aes_decrypt(encrypted_message, derived_key, iv) return decrypted_message


def start_session():
    """
Starts a new session with sending a ’Hello’ to the server.
Each session starts with a handshake. After the handshake is complete, encrypted messages are sent to the server.
"""


print("\nStarting client...")
time.sleep(1)
print("Client is up and running!")
hello_message = b"Hello"
sock.sendto(hello_message, (UDP_IP, UDP_PORT)) print(f"\nSent to server: {hello_message.decode()}") derived_key = ecdh_handshake()
send(input("\nUsername: "), derived_key, UDP_IP, UDP_PORT) send(input("Password: "), derived_key, UDP_IP, UDP_PORT) authentication_status = receive(derived_key)
print(f"\n[SERVER]: {authentication_status}")
if authentication_status == ’Successful authentication’:
send(input("\nSafe message to server: "), derived_key, UDP_IP, UDP_PORT) print("\n")
start_session()
