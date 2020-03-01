"""
    server.py - host an SSL server that checks passwords

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 140
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:

Vamshi Arugonda
Luke Bakken
Zachary Ryan

"""

import socket
import cryptography
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP as PKCS1_OAEP
from Crypto.Cipher import AES
import hashlib
hash_algo = hashlib.sha256()

host = "localhost"
port = 10001


# A helper function. It may come in handy when performing symmetric encryption
def pad_message(message):
    return message + " " * ((16 - len(message)) % 16)


# Write a function that decrypts a message using the server's private key
def decrypt_key(session_key):
    # TODO: Implement this function

    file = open("srv", "rb")
    externKey = file.read()
    file.close()

    server_private_key = RSA.importKey(externKey)

    #print(server_private_key)
    #sentinel = session_key

    handshake_cipher = PKCS1_OAEP.new(server_private_key)
    decrypted_handshake = handshake_cipher.decrypt(session_key)
    return decrypted_handshake


# Write a function that decrypts a message using the session key
def decrypt_message(client_message, session_key):
    # TODO: Implement this function

    #f = Fernet(session_key)
    #decrypted = f.decrypt(client_message)
    AES_cipher = AES.new(session_key, AES.MODE_EAX, "ASDFJKL;QWERYUIO".encode('utf-8'))
    decrypted = AES_cipher.decrypt(client_message).decode('utf-8')
    return decrypted


# Encrypt a message using the session key
def encrypt_message(message, session_key):
    # TODO: Implement this function

    #f = Fernet(session_key)
    #padded_message = pad_message(message)
    #encrypted = f.encrypt(padded_message.encode())
    AES_cipher = AES.new(session_key, AES.MODE_EAX, "ASDFJKL;QWERYUIO".encode('utf-8'))
    encrypted = AES_cipher.encrypt(message.encode('utf-8'))
    return encrypted


# Receive 1024 bytes from the client
def receive_message(connection):
    return connection.recv(1024)


# Sends message to client
def send_message(connection, data):
    if not data:
        print("Can't send empty string")
        return
    if type(data) != bytes:
        data = data.encode()
    connection.sendall(data)


# A function that reads in the password file, salts and hashes the password, and
# checks the stored hash of the password to see if they are equal. It returns
# True if they are and False if they aren't. The delimiters are newlines and tabs
def verify_hash(user, password):
    try:
        reader = open("passfile.txt", 'r')
        for line in reader.read().split('\n'):
            line = line.split("\t")
            if line[0] == user:
                # TODO: Generate the hashed password
                #hashed_password = hash(password+line[1])
                hash_algo.update(password.encode('utf-8'))
                hash_algo.update(line[1].encode('utf-8'))
                hashed_password = hash_algo.hexdigest()
                return hashed_password == line[2]
        reader.close()
    except FileNotFoundError:
        return False
    return False


def main():
    # Set up network connection listener
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    print('starting up on {} port {}'.format(*server_address))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)
    sock.listen(1)

    try:
        while True:
            # Wait for a connection
            print('waiting for a connection')
            connection, client_address = sock.accept()
            try:
                print('connection from', client_address)

                # Receive encrypted key from client
                encrypted_key = receive_message(connection)

                # Send okay back to client
                send_message(connection, "okay")

                # Decrypt key from client
                plaintext_key = decrypt_key(encrypted_key)

                # Receive encrypted message from client
                ciphertext_message = receive_message(connection)

                # TODO: Decrypt message from client
                text_message = decrypt_message(ciphertext_message, plaintext_key)

                # TODO: Split response from user into the username and password
                user = text_message.split(" ")[0]
                password = text_message.split(" ")[1]

                success = verify_hash(user, password)

                # TODO: Encrypt response to client
                if success:
                    text_response = "SUCCESS!"
                else:
                    text_response = "FAILURE!"
                ciphertext_response = encrypt_message(text_response, plaintext_key)

                # Send encrypted response
                send_message(connection, ciphertext_response)
            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()


if __name__ in "__main__":
    main()
