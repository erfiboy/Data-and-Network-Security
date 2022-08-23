# Secure Filesystem
This is a secure file system which store all the files and pathes encrypted in a filesystem and it has also the access control mechanism for user's
to restrict the access to a file of folder.

# Structure
It is a server-client base filesystem.
In the client side are files encrypted and decrypted with a unique key, which is created randomly and stored in the
client side, filesystem commands like ls, cd, ... are implemented in a secure and genric way inorder to work properly in different operataing systems.
All the messages between client and the server are encrypted using a shared key which is created with diffie-hellman key exchange algorithm when user signes up or logins.
