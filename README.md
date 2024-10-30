# SecureFileComm
A C++ client and Python server system enabling secure file storage and encrypted communication. The client registers with the server, exchanges encryption keys using traditional methods, and securely sends files for storage. Focused on reliable data handling and transmission protocols to protect client-server interactions.




Secure File Transfer System
This project is part of the Defensive Systems Programming course. It involves implementing a secure file transfer system with a client written in C++ and a server written in Python. The system allows clients to securely register, exchange encryption keys, and upload files to the server using encrypted communication.

Features
Client-Server Architecture: Clients initiate communication, exchange encryption keys with the server, and upload files.
Secure Communication: File transfer between the client and server is encrypted using AES and RSA.
Checksum Validation: The server verifies file integrity using checksum comparison.
Multi-client Support: The server handles multiple clients concurrently using Python's selector module.
Database Management: The server maintains a SQLite database to store user information and files.
System Requirements
Client: C++17, Visual Studio 2022
Server: Python 3.12, PyCryptodome library for encryption
Operating System: Windows (for client testing)
Development Tools:
Client: Visual Studio
Server: Python (compatible with the standard Python libraries)
Installation
Server
Ensure Python 3.12 is installed.

Install the required Python libraries using:

bash
Copy code
pip install pycryptodome
Place the port.info file in the same directory as the server code. This file should contain the port number for the server to listen on. Example content:

yaml
Copy code
1234
Run the server:

bash
Copy code
python server.py
Client
Open the project in Visual Studio.
Ensure C++17 is enabled.
The client will read server details from the transfer.info file, which should be placed in the same directory as the client executable. Example content:
makefile
Copy code
127.0.0.1:1234
John Doe
file_to_send.txt
Compile and run the client from Visual Studio.
Protocol Overview
Registration: Clients register with a username and a unique ID.
Public Key Exchange: Clients send their public RSA key to the server.
File Transfer: Clients send encrypted files to the server. The server verifies the file using checksum.
Reconnection: Clients can reconnect and continue from where they left off using their saved credentials.

Communication Protocol:
The protocol is binary, with all numeric fields being unsigned and transmitted in little-endian format. The primary fields include:

Client ID: Unique 16-byte identifier for each client.
Version: Client version.
Request Code: Indicates the type of request (e.g., registration, key exchange, file transfer).
Payload: Variable-sized data depending on the request type.
Refer to the protocol description in the docs folder for more details.

Usage
Start the server.
Run the client to register, exchange keys, and send files.
Use the logs to monitor communication between the client and server.
Database
The server uses an SQLite database defensive.db to store user and file information. The schema includes:

Clients table: Stores user details (ID, public key, last seen time, AES key).
Files table: Stores file details (file name, path, checksum status).
Testing


License
This project is for educational purposes as part of the Defensive Systems Programming course.
