import os
import re
import shutil
from pathlib import Path
from posixpath import split


def mkdir(path, client, access_control):
    os.makedirs(path)
    access_control.add_file(path)
    access_control.edit_access(client.user_name, path,0)
    return


def touch(path):
    Path(path).touch()
    return


def cd(path, client, access_control):
    os.chdir(path)
    access = access_control.get_access(client.user_name, path)
    if access in [0,1,2,3] :

        client.pwd = path
    return


def ls(path):
    return os.listdir(path)


def mv(src_path, dest_path, client, access_control, recursive=False):
    if access_control.get_access(client.user_name, src_path) == 0 :

        if os.path.isdir(src_path) and not recursive:
            return "Use -r to remove a directory!"

        shutil.move(src_path, dest_path)
    return


def rm(path, client , access_control, recursive=False):
    if access_control.get_access(client.user_name, path) == 0 :
        if os.path.isfile(path):
            os.remove(path)
        elif os.path.isdir(path) and not recursive:
            return "Use -r to remove a directory!"
        else:
            if recursive:
                for entry in os.scandir(path):
                    if entry.is_dir(follow_symlinks=False):
                        rm(entry.path, True)
                    else:
                        os.unlink(entry.path)

                os.rmdir(path)

def edit(path, client, access_control, edited_value):
    access = access_control.get_access(client.user_name, path)
    if access in [0,1,4,5]:
        rm(path, False, client, access_control)
        mkdir(path, client, access_control)
        fd = os.open(path, os.O_RDWR)
        line = str.encode(edited_value)
        numBytes = os.write(fd, line)
        
        os.close(fd)

def add_access(path, client, access_control, user_name, access) :
    if access_control.get_access(client.user_name, path) == 0 :
        
        access_control.edit_access(user_name, path, access)
    return
        
    
def save_file(content, path):
    directories, _ = os.path.split(path)
    mkdir(directories)
    with open(path, "w") as file:
        file.write(content)
    return True
    
def retrieve_file(path):
    if os.path.exists(path):
        with open(path, 'r') as file:
            content = file.read()
            return content
