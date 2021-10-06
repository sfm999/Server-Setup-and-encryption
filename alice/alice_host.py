import socket
import hashlib
import RC4
from secrets import token_hex
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP


divider = "%s" % ('~'*65)


# Function to send binary data to receiving socket
def send(data, port=3333, addr = '127.0.0.1'):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(data, (addr, port))


# Function to receive binary data from a socket
def receive(port=5555, addr='127.0.0.1', buf_size=2048):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((addr, port))

    while True:
        data, addr = s.recvfrom(buf_size)
        if data:
            return data


# Generates the authentication message that the host
# will send to users attempting to connect
def generate_authentication_message():
    with open('key.pem', 'rb') as fr:
        key = RSA.import_key(fr.read())
        fr.close()
    pkey = key.publickey().export_key().decode()

    return "Alice", pkey, generate_random_string(128), key


def connection_initiated(data):
    # Parse received csv data
    split_data = data.split(',')

    # Store individual variables
    rec_username = split_data[0]
    NB = split_data[1]

    # Send authentication details of host
    host_name, host_pk, NA, sk = generate_authentication_message()
    msg = host_name + ',' + host_pk + ',' + NA
    send(msg.encode())

    # Receive encrypted pw and K
    ciphertext = receive()

    # Create cipher using private key
    cipher = PKCS1_OAEP.new(sk)
    # Decrypt the received ciphertext
    msg = cipher.decrypt(ciphertext).decode()

    # Parse the decrypted message and set unique variables
    # for contents of parsed message
    split_msg = msg.split(',')
    rec_pw_hash = split_msg[0]
    K = split_msg[1]

    user_details = get_user_login(rec_username, rec_pw_hash)

    if not user_details:
        return


    if verify_user(user_details[0], rec_username, user_details[1], rec_pw_hash):
        print("| Connection successful!\n%s" % divider)
        send(b'Connection successful!')
    else:
        print("Connection failed!")
        send(b'Connection failed!')
        return

    # Compute shared secret key as H(K,NB,NA)
    ssk = K + ',' + NB + ',' + NA
    ssk = generate_hash(ssk.encode())

    return ssk


# Generates a random hex string of N bit length
def generate_random_string(bit_length):
    return token_hex(int(bit_length * 0.125))


# Wrapper function for hashlib.sha1()
# Returns hex representation of H(value)
def generate_hash(value):
    m = hashlib.sha1(value)
    return m.hexdigest()


# Searches stored login details and returns a matching user
# if one is found
def get_user_login(user, pw):
    with open('pw.pem', 'rb') as fr:
        lines = fr.readlines()
        fr.close()

    match = "%s:%s" % (user, pw)
    for x in lines:
        y = x.decode()
        if y == match:
            split_data = y.split(":")
            return split_data
    return None


def verify_user(su, ru, sp, rp):
    print("%s\n| Attempting to authenticate user joining network...\n%s" % (divider, divider))
    print("| Checking username against stored username...", end='')
    if su == ru:
        print("Username matches!\n%s\n| Checking password against stored password..." % divider, end='')
        if sp == rp:
            print("Password matches!\n%s" % divider)
            return True
        else:
            return False
    return False


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
        if plaintext == 'exit':
            print("Bob disconnected")
            return 'exit'
        print("Bob: %s" % plaintext)
        return plaintext
    else:
        print("Decryption error")
        return 'exit'


def wait():
    while True:
        print("Awaiting connection....")
        # Receive only returns if it gets valid data from socket
        data = receive().decode()
        if data:
            ssk = connection_initiated(data)
            if ssk:
                return ssk
            else:
                print("A user attempted to connect but failed...")
                send(b"Connection failed!")
                return False


def main():

    while True:
        ssk = wait()
        if ssk:
            # Automated welcome message
            send_message(ssk, "Welcome to my server!")
            print("Awaiting first message...")
            rec_msg = receive_message(ssk)
            while rec_msg != 'exit':
                msg = input("Enter a message to reply with: ")
                print("Alice: %s" % msg)
                send_message(ssk, msg)
                rec_msg = receive_message(ssk)





if __name__ == '__main__':
    main()
