"""
    add_user.py - Stores a new username along with salt/password

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    The solution contains the same number of lines (plus imports)

Vamshi Arugonda
Luke Bakken
Zachary Ryan

"""
import random
import hashlib
hash_algo = hashlib.sha256()
ALPH = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

def gen_salt():
    salt = ""
    for i in range( 16):
        salt += random.choice(ALPH)
    return salt


user = input("Enter a username: ")
password = input("Enter a password: ")

# TODO: Create a salt and hash the password
salt = gen_salt()
hash_algo.update(password.encode('utf-8'))
hash_algo.update(salt.encode('utf-8'))
hashed_password = hash_algo.hexdigest()

#hashed_password = hash(password+salt)

try:
    reading = open("passfile.txt", 'r')
    for line in reading.read().split('\n'):
        if line.split('\t')[0] == user:
            print("User already exists!")
            exit(1)
    reading.close()
except FileNotFoundError:
    pass

with open("passfile.txt", 'a+') as writer:
    writer.write("{0}\t{1}\t{2}\n".format(user, salt, hashed_password))
    print("User successfully added!")
