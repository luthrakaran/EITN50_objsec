import aes_encryption

# sends data using derived key and ip with port
def send(data, derived_key, destination_ip, destination_port, socket):
    # calls AES encryption method using data and derived key
    # and returns initalization vector and encoded encrypted data
    iv, encrypted_data = aes_encryption.encrypt(data, derived_key)
    
    # sends it via socket
    socket.sendto(iv, (destination_ip, destination_port))
    socket.sendto(encrypted_data, (destination_ip, destination_port))


def receive(derived_key, socket, bufferSize):
    # received encrypted data with iv
    iv, _ = socket.recvfrom(bufferSize)
    encrypted_data, _ = socket.recvfrom(bufferSize)
    
    # decrypts data with derived key and iv
    decrypted_data = aes_encryption.decrypt(
        encrypted_data, derived_key, iv)
    return decrypted_data
