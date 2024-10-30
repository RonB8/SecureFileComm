import os
import sqlite3
import datetime

class DataBase:
    def __init__(self, db_name="my_database.db", folder_name="client_files"):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.create_tables()

        #initialize the folder of the client files
        self.directory = folder_name
        # Create the directory if it does not exist
        os.makedirs(self.directory, exist_ok=True)

    # Create the 'clients' and 'files' tables
    def create_tables(self):
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            ID BLOB PRIMARY KEY,
            Name TEXT NOT NULL,
            PublicKey BLOB,
            LastSeen TEXT,
            AESKey BLOB
        )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                ID BLOB,
                FileName TEXT NOT NULL,
                PathName TEXT NOT NULL,
                Verified BOOLEAN NOT NULL DEFAULT 0,
                PRIMARY KEY (ID, FileName)
            )
        ''')

        self.conn.commit()

    # Add a new client and set LastSeen to the current time
    def add_client(self, client_id: bytes, name: str):
        last_seen = datetime.datetime.now().isoformat()
        self.cursor.execute('''
        INSERT INTO clients (ID, Name, LastSeen) 
        VALUES (?, ?, ?)
        ''', (client_id, name, last_seen))
        self.conn.commit()

    # Update the PublicKey of a client
    def set_public_key(self, client_id: bytes, public_key: bytes):
        self.cursor.execute('''
        UPDATE clients 
        SET PublicKey = ?
        WHERE ID = ?
        ''', (public_key, client_id))
        self.conn.commit()

    # Update the AESKey of a client
    def set_aes_key(self, client_id: bytes, aes_key: bytes):
        self.cursor.execute('''
        UPDATE clients 
        SET AESKey = ?
        WHERE ID = ?
        ''', (aes_key, client_id))
        self.conn.commit()

    # Add a new file to the 'files' table
    def add_file(self, client_id: bytes, file_name: str, path_name: str):
        self.cursor.execute('''
        INSERT INTO files (ID, FileName, PathName)
        VALUES (?, ?, ?)
        ''', (client_id, file_name, path_name))
        self.conn.commit()

    # Initialize the 'Verified' status of a file
    def set_crc_verified(self, client_id: bytes, file_name: str, verified: bool):
        self.cursor.execute('''
        UPDATE files 
        SET Verified = ?
        WHERE ID = ? and FileName = ?
        ''', (verified, client_id, file_name))
        self.conn.commit()

    # Function to retrieve a client by ID
    def get_client_by_id(self, client_id: bytes):
        self.cursor.execute('''
            SELECT ID, Name, LastSeen, PublicKey, AESKey FROM clients WHERE ID = ?
        ''', (client_id,))
        result = self.cursor.fetchone()  # Fetch the first matching row
        if result:
            return {
                'ID': result[0],
                'Name': result[1],
                'LastSeen': result[2],
                'PublicKey': result[3],
                'AESKey': result[4]
            }
        return None  # Return None if no client found


    # Function to retrieve a file by ID and file name
    def get_file(self, client_id: bytes, file_name: str):
        self.cursor.execute('''
               SELECT ID, FileName, PathName, Varified FROM files WHERE ID = ? and FileName = ?
           ''', (client_id, file_name))
        result = self.cursor.fetchone()  # Fetch the first matching row
        if result:
            return {
                'ID': result[0],
                'FileName': result[1],
                'PathName': result[2],
                'Varified': result[3]
            }
        return None  # Return None if no file found


    # Close the connection when done
    def close(self):
        self.conn.close()

    def save_file(self, file_name: object, content: object) -> object:
        file_path = os.path.join(self.directory, file_name)
        try:
            with open(file_path, 'w') as file:
                file.write(content)
            print(f'File "{file_name}" created successfully in "{self.directory}".')
        except Exception as e:
            print(f'Error creating file: {e}')
