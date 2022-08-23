from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def encryption(message: str, key, byte = None) -> bytes:
    cipher = AES.new(key, AES.MODE_EAX)
    
    if byte:
        cipher_text, tag = cipher.encrypt_and_digest(byte)
        return cipher.nonce, tag, cipher_text

    cipher_text, tag = cipher.encrypt_and_digest(message.encode())
    return cipher.nonce, tag, cipher_text

def decryption(cipher: bytes, key, byte = False) -> str:
    nonce = cipher[0]
    tag = cipher[1]
    cipher_text = cipher[2]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(cipher_text, tag)
    if byte:
        return data
    return data.decode()



