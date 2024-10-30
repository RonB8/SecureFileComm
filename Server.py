import socket

from PacketParser import PacketParser


class Server:
    def __init__(self, host, port):
        self.packet = None
        self.conn = None
        self.addr = None
        self.host = host
        self.port = port



    def start_listening(self):

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()

            while True:
                print("Waiting fot connection...")
                self.conn, self.addr = s.accept()
                packet = self.conn.recv(1024)
                return packet

    def send(self, packet):
        self.conn.sendall(packet)

    def close(self):
        self.conn.close()







