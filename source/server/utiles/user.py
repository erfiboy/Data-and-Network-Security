import hashlib


class user:
    def __init__(self, first_name, last_name, username, password) -> None:
        self.first_name = first_name
        self.last_name = last_name
        self.username = username
        self.password = hashlib.sha256(password.encode()).hexdigest()
        self.is_authenticated = False
