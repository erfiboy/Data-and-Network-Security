import getpass
import hashlib
import os
import pickle
import sys

from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
SCRIPT_DIR = os.path.dirname(os.path.abspath("./source/server"))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from ..server.main import ServerRun
from ..server.utiles.aes import decryption, encryption
from ..server.utiles.filesystem_commands import *
from ..server.utiles.session_key import KeyEchange


class Client():
    def __init__(self, username = None, password = None) -> None:
        self.username = username
        self.password = hashlib.sha256(password.encode()).hexdigest()
        self.master_key = None
        self.map_keys = dict()
        self.map_names = dict()
        self.pwd = os.path.join(os.getcwd(), "filesystem")
        self.base_path = os.path.join(os.getcwd(), "users_data")
        self.create_folder() 

    def dump(self):
        pickle.dump(encryption("", self.password[0:32].encode(), byte=self.master_key), 
            open(f"{self.base_path}//{self.username}.txt", 'wb'))

    def load(self):
        if os.path.exists(self.base_path+f"//{self.username}.txt"):
            self.master_key = pickle.load(open(f"{self.base_path}//{self.username}.txt", 'rb'))
            self.master_key = decryption(self.master_key, self.password[0:32].encode(), True)
        else:
            self.master_key = self.create_master_key()

    def create_folder(self):
        if os.path.exists(self.base_path):
            return
        os.makedirs(self.base_path)

    def create_master_key(self):
        self.master_key = get_random_bytes(32)

    def decrypt_file(self, path):
        try:
            path = directory_splitter(path)
            file_name = path[-1]

            for index, directory in enumerate(path):

                if directory in self.map_names.keys():
                    path[index] = self.map_names[directory]
                else:
                    return None

            encrypted_content = retrieve_file(os.path.join(*path))
            key = self.map_keys[file_name].encode()
            
            fernet = Fernet(key)
            content = fernet.decrypt(encrypted_content.encode()).decode()

            return content
        except Exception as e:
            print(e)
            return

    def encrypt_file(self, content, path):
        path = directory_splitter(path)
        file_name = path.pop()
        for index, directory in enumerate(path):
            if directory in self.map_names.keys():
                path[index] = self.map_names[directory]
            else:
                key = Fernet.generate_key()
                fernet = Fernet(key)
                name = fernet.encrypt(directory.encode()).decode()
                self.map_names[directory] = name
                path[index] = name
                self.map_keys[directory] = key.decode()

        if file_name in self.map_names.keys():
            path.append(self.map_names[file_name])
            save_file(encrypted_content, os.path.join(*path))
        else:
            key = Fernet.generate_key()
            fernet = Fernet(key) 
            name = fernet.encrypt(file_name.encode()).decode()  
            self.map_names[file_name] = name
            path.append(name)
            encrypted_content = fernet.encrypt(content.encode()).decode()
            self.map_keys[file_name] = key.decode()

            save_file(encrypted_content, os.path.join(*path))


def client_DH_key_exchange(server):
    client_DH = KeyEchange()
    client_pub_key = client_DH.get_pub_key()

    server_public_key, nonce, tag, cipher_text = server.server_DH_key_exchange(client_pub_key=client_pub_key)
    client_DH.calculate_share_key(server_public_key)
    session_key = client_DH.decrypt(cipher_text, tag, nonce)
    return session_key

def client_sign_up(server, session_key):
    first_name = input("Enter your user first name: ")
    last_name = input("Enter your user last name: ")
    username = input("Enter your user username: ")
    password = getpass.getpass("Enter your user password: ")
    client = Client(username, password)

    message = f"{first_name} {last_name} {username} {password}"
    cipher_text = encryption(message, session_key)
    is_signup = server.sign_up(cipher_text)
    return is_signup, client

def client_login(server, session_key):
    username = input("Enter your user username: ")
    password = getpass.getpass("Enter your user password: ")
    client = Client(username, password)

    message = f"{username} {hashlib.sha256(password.encode()).hexdigest()}"
    cipher_text = encryption(message, session_key)
    is_login = server.login(cipher_text)
    return is_login, client

def output_formatter(message, client):
    if not client:
        print(f"SecureFileSystem > {message}")
    else:
        print(f"{client.username}@{client.username}:  {client.pwd}$ {message}")

def filesystem_command(command: str, client):
    try:
        command_args = command.split(" ")
        path = None
        if len(command_args) == 1 and command_args[0] == "ls":
            path = os.getcwd()
        elif command_args[0] in ["rm", "mv"]:
            if command_args[1] == "-r" and len(command_args) == 3 and command_args[0] == "rm":
                path = os.path.abspath(command_args[2])
            elif len(command_args) == 2:
                path = os.path.abspath(command_args[2])
            elif command_args[1] == "-r" and len(command_args) == 4:
                path = [os.path.abspath(command_args[2]), os.path.abspath(command_args[3])]
            elif len(command_args) == 3:
                path = [os.path.abspath(command_args[1]), os.path.abspath(command_args[2])]
            else:
                path = re.findall('"([^"]*)"', command)        
                path = [os.path.abspath(i) for i in path]
                
        elif command_args[0] in ["mkdir", "touch", "cd", "setup", "ls"] and len(command_args) == 2:
            path = os.path.abspath(command_args[1])
        else:
            path = re.findall('"([^"]*)"', command)        
            path = [os.path.abspath(i) for i in path]

        if command_args[0] == "setup":
            mkdir(os.path.abspath(path))
            cd(os.path.abspath(path), client)

        elif command_args[0] == "mkdir":
            if not path:
                print("mkdir command only gets a path: ex, mkdir directory")
                return
            else:
                return mkdir(path)


        elif command_args[0] == "touch":
            if not path:
                print("touch command only gets a path: ex, touch file")
                return
            else:
                return touch(path)


        elif command_args[0] == "cd":
            if not path:
                print("cd command only gets a path: ex, cd directory")
                return
            else:
                return cd(path, client)


        elif command_args[0] == "ls":
            if not path:
                print("ls command gets a path or None: ex, cd directory")
                return
            else:
                return ls(path)

        elif command_args[0] == "rm":
            if command_args[1] == "-r":
                if not path:
                    print("rm command gets a path and a flag: ex, rm -r directory")
                    return
                else:
                    rm(path, True)
            else:
                if not path:
                    print("rm command gets a path and a flag: ex, rm -r directory")
                    return
                else:
                    rm(path, False)

        elif command_args[0] == "mv":
            if command_args[1] == "-r":
                if len(path) == 2:
                    return mv(path[0], path[1], True)
                else:
                    print("mv command gets a src path and a dest path and a flag: ex, mv -r src_directory dest_directory")
                    return
            else:
                if len(path) == 2:
                    return mv(path[0], path[1], False)
                else:
                    print("mv command gets a src path and a dest path and a flag: ex, mv src_file dest_file")
                    return
    except:
        return

def directory_splitter(path):
    folders = []
    while 1:
        path, folder = os.path.split(path)

        if folder != "":
            folders.append(folder)
        elif path != "":
            folders.append(path)

            break
            
    relative_path = folders[:folders.index("filesystem")]

    relative_path.reverse()
    return relative_path

def run():
    server = ServerRun()
    session_key = client_DH_key_exchange(server)
    input_message = None
    phase = "login"
    client = None
    while True:
        if phase == "login":
            input_message = "SecureFileSystem > [1] SignUp [2] Login: "
        elif phase == "authenticated":
            input_message = f"{client.username}@{client.username}: {client.pwd}$ "

        command = input(input_message)
        if command == "exit":
            if client:
                client.dump()
            phase = "login"
            client = None

        if phase == "login":
            try:
                command = int(command)
            except:
                continue
            if command == 1:
                is_signup, client = client_sign_up(server, session_key)
                if not is_signup:
                    output_formatter("The username already existed!", client)
                    client = None
                    continue
                else:
                    client.create_master_key()
                    phase = "authenticated"
                    filesystem_command(f"setup {client.pwd}", client)

            elif command == 2:
                is_login, client = client_login(server, session_key)
                if not is_login:
                    output_formatter("The username or password is wrong!", client)
                    client = None
                    continue
                else:
                    client.load()
                    phase = "authenticated"
                    filesystem_command(f"setup {client.pwd}", client)
                    
                    
            continue

        if phase == "authenticated":
            filesystem_command(command, client)
            client.encrypt_file("salam erfan", client.pwd+"/erfan/a.txt")
            print(client.decrypt_file(client.pwd+"/erfan/a.txt"))
while True:
    run()
