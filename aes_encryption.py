import base64
from Crypto.Cipher import AES
from Crypto import Random


def encrypt(data, key):
    # initialization vector
    iv = Random.new().read(AES.block_size)
    # Transform block cipher into stream cipher with CipherFeedBack
    cipher_suite = AES.new(key, AES.MODE_CFB, iv)
    secret_data = cipher_suite.encrypt(data)
    # encode encrypted data to base64 in order to transmit over socket
    encoded_secret_data = base64.b64encode(secret_data)

    return iv, encoded_secret_data


def decrypt(enc_data, key, iv):
    # generate cipher suite from iv and CFB
    cipher_suite = AES.new(key, AES.MODE_CFB, iv)
    # decode from base64
    decode_enc_data = base64.b64decode(enc_data)
    # decrypt data with cipher
    decrypted_data = cipher_suite.decrypt(
        decode_enc_data)

    return decrypted_data.decode()
