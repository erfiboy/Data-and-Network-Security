import logging

from Crypto.Random import get_random_bytes

from .utiles.aes import decryption, encryption
from .utiles.database import database
from .utiles.session_key import KeyEchange
from .utiles.user import user


class ServerRun:
    def __init__(self) -> None:
        self.session_key = None
        self.current_user = None
        self.database = database()
        
    def server_DH_key_exchange(self, client_pub_key):
        server_DH = KeyEchange()
        server_DH.calculate_share_key(client_pub_key)

        self.session_key = get_random_bytes(32)
        nonce, tag, cipher_text = server_DH.encrypt(self.session_key)
        server_public_key = server_DH.get_pub_key()
        return server_public_key, nonce, tag, cipher_text


    def sign_up(self, cipher_text):
        user_data = decryption(cipher_text, self.session_key)
        user_data = user_data.split(" ")
        
        if self.database.check_username(user_data[2]):
            logging.error("User with this username already existed!")
            return False

        self.current_user = user(user_data[0], user_data[1], user_data[2], user_data[3])
        self.database.add_user(self.current_user)
        logging.info(f"Sign up successfully, {user_data[2]}")
        return True

    def login(self, cipher_text):
        user_data = decryption(cipher_text, self.session_key)
        user_data = user_data.split(" ")
        if not self.database.check_username(user_data[0]):
            logging.error("User with this username doesn't existed.")
            return False

        self.current_user = self.database.get_user(user_data[0], user_data[1])
        logging.info(f"Login successfully, {user_data[0]}")
        return True
