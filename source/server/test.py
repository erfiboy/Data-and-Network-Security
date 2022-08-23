import getpass
import hashlib
import os
import pickle

from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet
from main import ServerRun
from utiles.aes import decryption, encryption
from utiles.filesystem_commands import *
from utiles.session_key import KeyEchange


def names_encrypted(path):
    folders = []
    while 1:
        path, folder = os.path.split(path)

        if folder != "":
            folders.append(folder)
        elif path != "":
            folders.append(path)

            break
            
    relative_path = folders[:folders.index("filesystem")]
    for i in range(len(relative_path)):
        key = Fernet.generate_key()
        print(key.decode())
        fernet = Fernet(key)
        relative_path[i] = fernet.encrypt(relative_path[i].encode())
        print(relative_path[i])
        relative_path[i] = fernet.decrypt(relative_path[i]).decode()
        
    relative_path.reverse()
    return relative_path


print(names_encrypted("/etc/bin/filesystem/mamad/erfan.txt"))
