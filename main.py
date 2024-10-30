import socket
import base64
from http.client import responses
# from http.cookiejar import request_host

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.SelfTest.Cipher.test_CFB import file_name
from Crypto.Util.Padding import pad

from ByteFuncs import push_as_n_bytes
from DataBase import DataBase
from RequestHandler import RequestHandler
from Server import Server
# from crypto.Cipher import AES
# from crypto.Random import get_random_bytes
# from crypto.Util.Padding import pad

from User import *
from PacketParser import *
import warnings
import threading
from Payload import Payload
from Respone import *
from bdika import dataBase
from cksum import checksum, memcrc
from converter import public_key_blob_to_der
from myEncryption import*

users_list = Users()

HOST = ''
PORT = 1256  # default port #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
DEFAULT_PORT = 1256  # default port


def send(conn, message):
    # reply_data = bytearray(message, "utf-8")
    conn.sendall(message)
    # conn.sendall(message)


def printArr(arr):
    index = 0
    for var in arr:
        if var != 0:
            print(f'[{index}] = {var}')
        index += 1


def handle_client(conn, addr):
    with (conn):
        print('Connected by', addr)

        packet = conn.recv(1024)
        # text = data.decode("utf-8")
        # printArr(list(packet))
        req = PacketParser(packet)

        if req.code == REGISTRY:
            id = users_list.register(req.get_name())
            if id is None:
                response = Response(DEFAULT_VERSION, FAILED_REGISTRATION, 0, {})
            else:
                # printArr(id)
                payload = Payload(c_id=id)
                response = Response(DEFAULT_VERSION, SUCCESSFUL_REGISTRATION, len(payload.packet), payload.packet)

        elif req.code == SEND_PUBLIC_KEY:
            print("Got public key") #@@@@@@@@@@@
            pub_key = req.get_public_key()
            usr = users_list.get_user(req.client_ID)
            # aes_key = usr.generate_aes_key() #@@@@@@@@@@@@@@@@@

            aes_key = bytearray([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1])


            print("The aes key is:\n")
            # printArr(aes_key)
            print(list(aes_key))
            encrypted_aes_key = encrypt_rsa(pub_key, aes_key)

            payload = Payload(req.client_ID, encrypted_aes_key=encrypted_aes_key)
            payload_size = 16 + len(encrypted_aes_key)
            response = Response(DEFAULT_VERSION, PUBLIC_KEY_RECEIVED, len(payload.packet), payload.packet)



        elif req.code == LOGIN:
            payload = Payload(c_id=req.client_ID, encrypted_aes_key=None, content_size=300, file_name="basbusa", cksum=9513)
            response = Response(DEFAULT_VERSION, VALID_FILE_ACCEPTED, len(payload.packet), payload.packet)

        elif req.code == SEND_FILE:
            print("Got file")
            usr = users_list.get_user(req.client_ID)

            # decrypted_content = usr.aes_cipher.decrypt(req.get_message_content())
            decrypted_content = req.get_message_content() #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

            temp_file_name = 'temp.txt'
            temp_file = open(temp_file_name, 'w')
            temp_file.write("decrypted_content")
            temp_file.close()
            curr_check_sum = checksum(temp_file.name)

            payload = Payload(c_id=req.client_ID, content_size=req.get_content_size(), file_name=req.file_name(), cksum=curr_check_sum)
            response = Response(DEFAULT_VERSION, VALID_FILE_ACCEPTED, len(payload.packet), payload.packet)

        elif req.code in {VALID_CRC, FOURTH_INVALID_CRC}:
            print("Executing CRC validation")
            payload = Payload(c_id=req.client_ID)
            response = Response(DEFAULT_VERSION, MESSAGE_RECEIVED, len(payload.packet), payload.packet)

        elif req.code == INVALID_CRC:
            print("Invalid CRC")
            payload = Payload(c_id=req.client_ID)
            response = Response(DEFAULT_VERSION, MESSAGE_RECEIVED, len(payload.packet), payload.packet) #@@@@@@@@@@@@@@@

        send(conn, response.packet)

        conn.close()


def start_server(host, port):
    port = PORT
    file_name = "port.info"
    # file_name = "ss.txt"
    try:
        f = open(file_name, 'r')
        port = int(f.read())
        f.close()
    except:
        warnings.warn(f'The \'{file_name}\' file does not exist')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, port))
        s.listen()

        while True:
            print("Waiting fot connection...")
            conn, addr = s.accept()

            # client_thread = threading.Thread(target=handle_client, args=(conn, addr,))
            # client_thread.start()

            handle_client(conn, addr)






if __name__ == "__main__":



    port = DEFAULT_PORT
    host = HOST
    file_name = "port.info"
    try:
        with open(file_name, 'r', encoding='utf-16') as f:
            content = f.read()
            port = int(content)
    except FileNotFoundError:
        warnings.warn(f'The \'{file_name}\' file does not exist')
    except ValueError:
        warnings.warn(f'The content of \'{file_name}\' is not a valid integer')



    users_list2 = Users()
    data_base = DataBase()
    request_handler = RequestHandler(users_list2, data_base)

    while True:

        server = Server(host, port)
        packet = server.start_listening()
        request = PacketParser(packet)

        request_handler = RequestHandler(users_list2, data_base)
        response = request_handler.handle_request(request)

        # If the request is a packet from a file and the file has not yet arrived in its entirety, the response is None
        if response is not None:
            server.send(response)
        server.close()


