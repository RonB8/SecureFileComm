
from DataBase import DataBase
from RequestHandler import RequestHandler
from RequestParser import *
import socket
import threading
from RequestParser import RequestParser
from Response import Response
from User import UserRepository

#Sets the longest possible request.
CONTENT_PACKET_SIZE = 4000
SEND_FILE_HEADER = 290
MAX_REQUEST_SIZE = CONTENT_PACKET_SIZE + SEND_FILE_HEADER


class Server:
    """
    A class used to manage communication with clients.

    The Server class is responsible for setting up the server socket, accepting connections,
    and handling client requests concurrently. It processes incoming packets, parses them,
    and responds to clients with appropriate responses.

    Attributes:
    ----------
    host : str
        The IP address or hostname where the server will listen for connections.
        This can be a local address such as 'localhost' or '127.0.0.1', or a public IP address.
    port : int
        The port number on which the server will listen. Typically, a number between 1024 and 65535.
    user_list : UserRepository
        An instance of UserRepository used to store and manage users.
    data_base : DataBase
        An instance of DataBase used to manage the storage of users' information and files.
    request_handler : RequestHandler
        An instance of RequestHandler used to handle and process requests from clients.

    Methods:
    --------
    start_listening():
        Starts the server and listens for incoming client connections.
        For each connection, it spawns a new thread to handle the client independently.

    handle_client(conn: socket.socket, addr: tuple):
        Handles a single client's request. Receives a packet from the client, parses it,
        and sends back the appropriate response.
    """

    def __init__(self, host: str, port: int) -> None:
        self.host: str = host
        self.port: int = port
        self.user_list = UserRepository()
        self.data_base = DataBase()
        self.request_handler = RequestHandler(self.user_list, self.data_base)

    def start_listening(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            print(f"Server listening on {self.host}:{self.port}...")

            while True:
                conn, addr = s.accept()
                print(f"Connected to {addr}")

                # Start a new thread for each client
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_thread.start()

    def handle_client(self, conn: socket.socket, addr: tuple) -> None:
        try:
            packet = conn.recv(MAX_REQUEST_SIZE)

            if not packet:
                print(f"No data received from {addr}. Closing connection.")
                return

            # Process the packet (this is where you can integrate with RequestParser)
            request = RequestParser(packet)
            # Handle the request and get the response
            response = self.request_handler.handle_request(request)

            if response is None:
                error_response = Response(DEFAULT_VERSION, GENERIC_ERROR, 0, bytearray())
                conn.sendall(error_response.get_packet())  # pong
            else:
                conn.sendall(response)
                print(f"Response sent to {addr}")

        except socket.error as e:
            print(f"Error handling client {addr}: {e}")
        finally:
            conn.close()
            print(f"Connection with {addr} closed.")




