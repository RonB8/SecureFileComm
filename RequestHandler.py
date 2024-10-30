from logging import raiseExceptions
from urllib.request import Request

from DataBase import DataBase
from PacketParser import*
from Payload import Payload
from Respone import Response
from User import Users
from bdika import dataBase
from cksum import checksum
# from main import printArr
from myEncryption import encrypt_rsa


def unpad(data):
    padding_len = data[-1]  # הערך האחרון הוא גודל הריפוד
    return data[:-padding_len]

class RequestHandler:
    def __init__(self, users_list:Users, data_base:DataBase):
        self.users_list = users_list
        self.data_base = data_base

    def handle_request(self, request:PacketParser):
        global response

        curr_code = request.code
        if curr_code not in {REGISTRY, SEND_PUBLIC_KEY, LOGIN, SEND_FILE, VALID_CRC, INVALID_CRC, FOURTH_INVALID_CRC}:
            raise ValueError(f"Error: Code {curr_code} invalid.")

        if request.code == REGISTRY:
            curr_user = self.users_list.register(request.get_name())
            if curr_user is None:
                response = Response(DEFAULT_VERSION, FAILED_REGISTRATION, 0, {})
            else:
                self.data_base.add_client(curr_user.get_id(), curr_user.get_name())
                new_id = curr_user.get_id()
                payload = Payload(c_id=new_id)
                response = Response(DEFAULT_VERSION, SUCCESSFUL_REGISTRATION, len(payload.packet), payload.packet)
        else:
            curr_user = self.users_list.get_user(request.client_ID)
            #Exception @@@@@@@@@@@@@@@


            if curr_code == SEND_PUBLIC_KEY:
                print("Got public key") #@@@@@@@@@@@

                pub_key = request.get_public_key()

                self.data_base.set_public_key(curr_user.get_id(), pub_key)
                curr_user.set_public_key(pub_key)

                aes_key = curr_user.generate_aes_key() #@@@@@@@@@@@@@@@@@
                self.data_base.set_aes_key(curr_user.get_id(), aes_key)

                print("The aes key is:")
                print(list(aes_key))

                encrypted_aes_key = encrypt_rsa(pub_key, aes_key)
                print(f"\nThe length of the encrypted aes key is: {len(encrypted_aes_key)}\n")
                # print(list(encrypted_aes_key))
                # printArr(encrypted_aes_key)

                payload = Payload(request.client_ID, encrypted_aes_key=encrypted_aes_key)
                # payload_size = 16 + len(encrypted_aes_key)
                response = Response(DEFAULT_VERSION, PUBLIC_KEY_RECEIVED, len(payload.packet), payload.packet)



            elif curr_code == LOGIN:
                print("Login...")
                curr_user = self.users_list.get_user(request.client_ID)

                if curr_user is None:
                    raise Exception("Login failed, user doesn't exist!")

                aes_key = curr_user.generate_aes_key()
                encrypted_aes_key = encrypt_rsa(curr_user.get_public_key(), aes_key)
                payload = Payload(c_id=request.client_ID, encrypted_aes_key=encrypted_aes_key)
                response = Response(DEFAULT_VERSION, LOGIN_ACCEPT, len(payload.packet), payload.packet)

            elif curr_code == SEND_FILE:
                print("Got file")
                encrypted_packet = request.get_message_content()
                curr_user.append_to_temp_encrypted_content(encrypted_packet)

                print(f"Packet {request.get_packet_number()} from {request.total_packets()}")

                if request.get_packet_number() < request.total_packets():
                    return None #If the file has not yet arrived in its entirety, there is no response

                else:
                    encrypted_content = curr_user.get_temp_encrypted_content()
                    decrypted_content = curr_user.aes_cipher.decrypt(encrypted_content)
                    decrypted_content = unpad(decrypted_content)
                    str_content = decrypted_content.decode()
                    # print(f"Decrypted_content: {str_content}")
                    curr_user.set_temp_content(str_content)
                    curr_user.clear_temp_encrypted_content()

                    temp_file_name = 'temp.txt'
                    temp_file = open(temp_file_name, 'w')
                    temp_file.write(str_content)
                    temp_file.close()
                    curr_check_sum = checksum(temp_file.name)

                    payload = Payload(c_id=request.client_ID, content_size=request.get_content_size(), file_name=request.file_name(), cksum=curr_check_sum)
                    response = Response(DEFAULT_VERSION, VALID_FILE_ACCEPTED, len(payload.packet), payload.packet)



            elif curr_code == VALID_CRC:
                print("Valid CRC")
                self.data_base.set_crc_verified(request.client_ID, request.file_name(), True)
                content = curr_user.get_temp_content()
                dataBase.save_file(request.file_name(), content)
                curr_user.set_temp_content(None)
                payload = Payload(c_id=request.client_ID)
                response = Response(DEFAULT_VERSION, MESSAGE_RECEIVED, len(payload.packet), payload.packet)



            elif curr_code == FOURTH_INVALID_CRC:
                print("Fourth invalid CRC")
                curr_user.set_temp_content(None)
                payload = Payload(c_id=request.client_ID)
                response = Response(DEFAULT_VERSION, MESSAGE_RECEIVED, len(payload.packet), payload.packet)

            elif curr_code == INVALID_CRC:
                print("Invalid CRC")
                payload = Payload(c_id=request.client_ID)
                response = Response(DEFAULT_VERSION, MESSAGE_RECEIVED, len(payload.packet), payload.packet) #@@@@@@@@@@@@@@@

        return response.packet
