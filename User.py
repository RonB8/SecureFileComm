import uuid

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# from main import users_list


class User:
    def __init__(self, id: bytes, name: str):
        self.__id = id
        self.__name = name
        self.public_key = None
        self.aes_cipher = None
        self.aes_key = None
        self.temp_encrypted_content = bytearray([])
        self.temp_content = None

    def get_id(self) -> bytes:
        return self.__id

    def get_name(self):
        return self.__name

    def generate_aes_key(self):
        self.aes_key = get_random_bytes(32)

        #For the purpose of the project, the client assumes that the IV
        #is always filled with 0, although this is not a sure thing
        iv = bytearray([0 for _ in range(16)])

        self.aes_cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        return self.aes_key

    def get_aes_key(self):
        return self.aes_key

    def set_public_key(self, pub_key):
        self.public_key = pub_key

    def get_public_key(self):
        return self.public_key

    def append_to_temp_encrypted_content(self, content:bytearray):
        self.temp_encrypted_content += content[:]

    def get_temp_encrypted_content(self):
        return self.temp_encrypted_content[:]

    def set_temp_content(self, content):
        self.temp_content = content

    def get_temp_content(self):
        return self.temp_content

    def clear_temp_encrypted_content(self):
        self.temp_encrypted_content.clear()


class Users:
    def __init__(self):
        self.users_list = []
        self.id_list = []

    def register(self, name: str):
        if any(usr.get_name() == name for usr in self.users_list):
            print(f"The user {name} already exist")
            return None

        new_id = uuid.uuid4()
        while new_id in self.id_list:
            new_id = uuid.uuid4()

        self.id_list.append(new_id)
        new_user = User(new_id.bytes, name)
        self.users_list.append(new_user)
        print(f"Registering {name}")
        return new_user

    def get_user(self, c_id: bytes) ->User:
        for usr in self.users_list:
            curr_id = usr.get_id()
            if c_id == curr_id:
                return usr

        return None


