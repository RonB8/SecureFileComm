import re


class PacketParser:
    def __init__(self, packet):
        self.client_ID = packet[:16]
        self.version = int.from_bytes(packet[16:17], byteorder='big')
        self.code = int.from_bytes(packet[17:19], byteorder='big')
        self.payload_size = int.from_bytes(packet[19:23], byteorder='big')
        self.payload = packet[23:]


    def get_name(self):
        if self.code not in(REGISTRY, SEND_PUBLIC_KEY, LOGIN):
            raise Exception('..') #@@@@@@@@@@@@@@@@@@@@@@@@ to change

        name = self.payload[:256].decode()
        name = name.replace('\0', '')
        return name

    def get_public_key(self):
        if self.code != SEND_PUBLIC_KEY:
            raise Exception('..') #@@@@@@@@@@@@@@@@@@@@@@@@ to change

        res = self.payload[255: 415]
        return res

    def get_content_size(self):
        if self.code != SEND_FILE:
            raise Exception('..')  # @@@@@@@@@@@@@@@@@@@@@@@@ to change

        res = self.payload[:4]
        res = int.from_bytes(res)
        return res

    def get_orig_file_size(self):
        if self.code != SEND_FILE:
            raise Exception('..')  # @@@@@@@@@@@@@@@@@@@@@@@@ to change

        res = self.payload[4: 8]
        res = int.from_bytes(res)
        return res

    def get_packet_number(self):
        if self.code != SEND_FILE:
            raise Exception('..')  # @@@@@@@@@@@@@@@@@@@@@@@@ to change

        res = self.payload[8: 10]
        res = int.from_bytes(res)
        return res

    def total_packets(self):
        if self.code != SEND_FILE:
            raise Exception('..')  # @@@@@@@@@@@@@@@@@@@@@@@@ to change

        res = self.payload[10: 12].decode()
        res = res.replace('\0', '')
        return ord(res)

    def file_name(self):
        if self.code not in (SEND_FILE, VALID_CRC, INVALID_CRC, FOURTH_INVALID_CRC):
            raise Exception('..')  # @@@@@@@@@@@@@@@@@@@@@@@@ to change

        if self.code == SEND_FILE:
            res = self.payload[12: 267].decode()

        else:
            res = self.payload[: 255].decode()

        res = res.replace('\0', '')
        return res

    def get_message_content(self):
        if self.code != SEND_FILE:
            raise Exception('..')  # @@@@@@@@@@@@@@@@@@@@@@@@ to change

        content_size = self.get_content_size()
        start_content = 267
        end_content = start_content + content_size

        res = self.payload[start_content: end_content]
        # res = res.replace('\0', '')
        return res



# Constants for default version and payload size
DEFAULT_VERSION = 3
DEFAULT_PAYLOAD_SIZE = 300

# Command codes
REGISTRY = 825
SEND_PUBLIC_KEY = 826
LOGIN = 827
SEND_FILE = 828
VALID_CRC = 900
INVALID_CRC = 901
FOURTH_INVALID_CRC = 902

# Status codes
SUCCESSFUL_REGISTRATION = 1600
FAILED_REGISTRATION = 1601
PUBLIC_KEY_RECEIVED = 1602
VALID_FILE_ACCEPTED = 1603
MESSAGE_RECEIVED = 1604
LOGIN_ACCEPT = 1605
LOGIN_DENIED = 1606
GENERIC_ERROR = 1607
