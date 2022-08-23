from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import AES
class KeyEchange:
    parameters = dh.generate_parameters(generator=2, key_size=2048)

    def __init__(self) -> None:
        self.private_key = KeyEchange.parameters.generate_private_key()
        self.shared_key = None

    def get_parameter(self):
        return self.parameters
        
    def get_pub_key(self):
        return self.private_key.public_key()

    def calculate_share_key(self, client_pub_key):
        self.shared_key = self.private_key.exchange(client_pub_key)

    def decrypt(self, message, tag, nonce):
        key  = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(self.shared_key)
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        message = cipher.decrypt_and_verify(message, tag)
        return message

    def encrypt(self, message):
        key  = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(self.shared_key)
        cipher = AES.new(key, AES.MODE_EAX)
        cipher_text, tag = cipher.encrypt_and_digest(message)
        return cipher.nonce, tag, cipher_text

