"""
    client.py - Connect to an SSL server

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 117
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:

Vamshi Arugonda
Luke Bakken
Zachary Ryan

"""

import socket
import os

import secrets
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP as PKCS1_OAEP
from Crypto.Cipher import AES


host = "localhost"
port = 10001


# A helper function that you may find useful for AES encryption
# Is this the best way to pad a message?!?!
def pad_message(message):
    return message + " "*((16-len(message))%16)


# TODO: Generate a cryptographically random AES key
def generate_key():
    # TODO: Implement this function
    return secrets.token_bytes(16)


# Takes an AES session key and encrypts it using the appropriate
# key and return the value
def encrypt_handshake(session_key):
    # TODO: Implement this function
    file = open("../server/srv.pub", "rb")
    externKey = file.read()
    file.close()

    server_public_key = RSA.importKey(externKey)

    #print(server_public_key)

    handshake_cipher = PKCS1_OAEP.new(server_public_key)
    encrypted_handshake = handshake_cipher.encrypt(session_key)
    return encrypted_handshake


# Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
    # TODO: Implement this function
    AES_cipher = AES.new(session_key, AES.MODE_EAX, "ASDFJKL;QWERYUIO".encode('utf-8'))
    encrypted = AES_cipher.encrypt(message.encode('utf-8'))
    return encrypted


# Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    # TODO: Implement this function
    AES_cipher = AES.new(session_key, AES.MODE_EAX, "ASDFJKL;QWERYUIO".encode('utf-8'))
    decrypted = AES_cipher.decrypt(message).decode('utf-8')
    return decrypted


# Sends a message over TCP
def send_message(sock, message):
    sock.sendall(message)


# Receive a message from TCP
def receive_message(sock):
    data = sock.recv(1024)
    return data


def main():
    user = input("What's your username? ")
    password = input("What's your password? ")

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    try:
        # Message that we need to send
        message = user + ' ' + password

        # Generate random AES key
        key = generate_key()

        # Encrypt the session key using server's public key
        encrypted_key = encrypt_handshake(key)

        # Initiate handshake
        send_message(sock, encrypted_key)

        # Listen for okay from server (why is this necessary?)
        if receive_message(sock).decode() != "okay":
            print("Couldn't connect to server")
            exit(0)

        # TODO: Encrypt message and send to server
        message = encrypt_message(message, key)
        send_message(sock, message)

        # TODO: Receive and decrypt response from server
        received = receive_message(sock)
        decrypted = decrypt_message(received, key)
        print(decrypted)

    finally:
        print('closing socket')
        sock.close()

if __name__ in "__main__":
    main()
