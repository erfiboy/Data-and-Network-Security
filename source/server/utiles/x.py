import hashlib

from database import database
from user import user

db = database("erfan.db")

db.create_connection()
db.create_user_table()
client = user("erfan", "nosrati", "erfiboy", "44403773", "aojodfasadsfsaf", "wrfd2")

db.add_user(client)
mamad = db.get_user("erfiboy", hashlib.sha256(b"44403773").hexdigest())

print(mamad.__dict__)
