
import sys, socket, hashlib, RC4
from getpass import getpass
from secrets import token_hex
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA

# Function sends messages to alice's port
def send(data, port=5555, addr = '127.0.0.1'):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(data, (addr, port))


# Function receives messages on Bob's port from Alice
def receive(port=3333, addr='127.0.0.1', buf_size=1024):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((addr, port))

    while True:
        data, addr = s.recvfrom(buf_size)
        if data:
            return data


def generate_hash(value):
    m = hashlib.sha1(value)
    return m.hexdigest()


def generate_random_string(bit_length):
    return token_hex(int(bit_length * 0.125))


def get_fingerprint():
    with open('alice_fingerprint.pem', 'r') as fr:
        fingerprint = fr.read()
        fr.close()
    return fingerprint


def get_user_login():
    # Prompt username and password
    username = input("Enter your username: ")
    NB = generate_random_string(128)

    return username, NB


def get_pw_and_K():
    pw = generate_hash(getpass('Enter your password: ').encode())
    K = generate_random_string(128)
    return pw, K


def generate_checksum(ssk, msg):
    checksum = ssk + "," + msg
    return generate_hash(checksum.encode())


# recsum comes in as a hash str obj, ssk as a str obj, msg as a str obj.
# Simply compares two hashvalues and returns true if equal else false
def verify_checksum(recsum, ssk, msg):
    checksum = generate_checksum(ssk, msg)
    if checksum == recsum:
        return True
    else:
        return False


def send_message(ssk, msg):
    # Compute h = H(ssk, msg)
    # Then compute C = encryption of m & h with RC4 using
    # our ssk as the key for encryption.

    # Generate h = H(ssk, msg)
    h = generate_checksum(ssk, msg)

    C = RC4.encrypt(ssk, (msg + ';;' + h))
    send(C.encode())


def receive_message(ssk):
    ciphertext = receive().decode()
    rec_msg = RC4.decrypt(ssk, ciphertext).split(";;")
    plaintext = rec_msg[0]
    recsum = rec_msg[1]

    if verify_checksum(recsum, ssk, plaintext):
        print("Alice: %s" % plaintext)
        return plaintext
    else:
        print("Decryption error")
        return 'exit'


def main():

    # Prompt the user to input login details and send result
    username, NB = get_user_login()
    msg = username + ',' + NB
    send(msg.encode())

    # Await server response
    data = receive().decode()

    # Parse received host data and set unique variables with contents  
    host_details = data.split(",")
    host_name = host_details[0]
    host_pk = host_details[1]
    NA = host_details[2]

    # Generate a hash of the received public key
    rec_hash_val = generate_hash(host_pk.encode())

    # If H(rec pk) doesn't match the stored H(pk) of server
    if rec_hash_val != get_fingerprint():
        print('The received servers public key, when hashed, did not match the stored hash of the servers public key you have.')
        print('Server may be compromised. Program exiting now.')
        exit()

    # To reach here, H(rec pk) == H(pk) stored locally
    # Now we perform RSA encryption of the password

    # Instantiate host_pk as object of RSA
    # Create session key as random 128 bit string of hex
    host_pk = RSA.import_key(host_pk)
    session_key = generate_random_string(128).encode()

    # Create the cipher object with receiver_key
    cipher_rsa = PKCS1_OAEP.new(host_pk)
    # Get contents of authentication message and encrypt it
    pw, K = get_pw_and_K()
    msg = pw + ',' + K
    ciphertext = cipher_rsa.encrypt(msg.encode())

    # Send encrypted data
    send(ciphertext)

    # Await the confirmation or declination of attempted verification
    # and subsequent connection
    data = receive().decode()
    # Display result
    if data == "Connection failed!":
        print(data, " Program exiting now...")
        exit()


    # Compute shared secret key as H(K,NB,NA)
    ssk = K + ',' + NB + ',' + NA
    ssk = generate_hash(ssk.encode())

    msg = receive_message(ssk)

    while msg != 'exit':
        msg = input("Enter a message to reply with or enter 'exit' to quit: ")
        if msg == 'exit':
            send_message(ssk, msg)
            exit()
            break
        print("Bob: %s" % msg)
        send_message(ssk, msg)
        msg = receive_message(ssk)


if __name__ == '__main__':
    main()
