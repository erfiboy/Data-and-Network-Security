import os
import sqlite3
from sqlite3 import Error

from .log import logger
from .user import user


class database:
    
    def __init__(self, db_path=None) -> None:
        self.db_path = os.getcwd() + "/" + db_path if db_path else (os.getcwd() + "/database/")
        self.conn = None
        self.create_connection()
        self.create_user_table()
        self.uid = self.get_last_uid()

    def create_connection(self):
        try:
            if not os.path.exists(self.db_path):
                os.makedirs(self.db_path)
            self.conn = sqlite3.connect(self.db_path + "user.db")
            logger.info(f"Trying to connect to database. path: {self.db_path}user.db")
        except Error as e:
            self.conn = None
            logger.error(e)

    def close_connection(self):
        if not self.conn:
            logger.error("There is no connection to be closed.")
        self.conn.close()

    def create_user_table(self):
        if not self.conn:
            logger.info("Creating the database before add a table!")
            self.create_connection()

        try:
            self.conn.execute(
                """CREATE TABLE USER
            (
                id INT PRIMARY KEY     NOT NULL,
                first_name           TEXT     NOT NULL,
                last_name            TEXT     NOT NULL,
                username             TEXT     NOT NULL,
                password             TEXT     NOT NULL);
                """
            )
        except Error as e:
            logger.error(e)

    def add_user(self, user):
        try:
            self.uid += 1
            query = f"INSERT INTO USER (id,first_name,last_name,username,password) \
                VALUES ({self.uid}, '{user.first_name}', '{user.last_name}', '{user.username}', '{user.password}');"
            print(query)
            self.conn.execute(query)
            self.conn.commit()
        except Error as e:
            logger.error(e)

    def get_user(self, username, password):
        try:
            query = f"SELECT * from USER WHERE  username = '{username}' AND password = '{password}';"
            cursor = self.conn.execute(query)
            rows = cursor.fetchall()
            logger.info(query)
            for row in rows:   
                logger.error(row)
                return user(row[1], row[2], row[3], row[4])

        except Error as e:
            logger.error(e)

    def check_username(self, username):
        try:
            query = f"SELECT * from USER WHERE  username = '{username}';"
            cursor = self.conn.execute(query)

            rows = cursor.fetchall()
            return True if len(rows) else False
        except Error as e:
            logger.error(e)

    def get_last_uid(self):
        try:
            query = "SELECT * from USER;"
            cursor = self.conn.execute(query)
            rows = cursor.fetchall()
            id_max = 0
            for row in rows:
                if row[0] > id_max:
                    id_max = row[0]
            return id_max
        except Error as e:
            logger.error(e)
            return 0

    def create_ACL_table(self):
        if not self.conn:
            logger.info("Creating the database before add a table!")
            self.create_connection()
 
        try:
            self.conn.execute(
                """CREATE ACL USER
            (
                id INT PRIMARY KEY     NOT NULL,
                file_name           TEXT     NOT NULL,
                user_id             integer NOT NULL
                write               integer NOT NULL,
                read                integer NOT NULL,
                execute             integer NOT NULL);
                """
            )
        except Error as e:
            logger.error(e)