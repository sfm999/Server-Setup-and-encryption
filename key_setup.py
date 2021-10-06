
import hashlib
from Crypto.PublicKey import RSA


def distribute_resources():
    key = generate_key()

    # Write Alice's private key to her directory
    with open('alice/key.pem', 'wb') as fw:
        fw.write(key.export_key('PEM'))
        fw.close()

    # Write Alice's pk hash to bob's directory
    with open('bob/alice_fingerprint.pem', 'wb') as fw:
        fw.write(generate_fingerprint(key))
        fw.close()

    # Write password_file
    with open('alice/pw.pem', 'wb') as fw:
        fw.write(b'Bob:')
        fw.write(generate_hash('pass1234'))
        fw.close()


def generate_key():
    return RSA.generate(2048)


def generate_hash(value):
    m = hashlib.sha1(value.encode())
    return m.hexdigest().encode()


def generate_fingerprint(key):
    m = hashlib.sha1(key.publickey().export_key())
    return m.hexdigest().encode()


def main():
    distribute_resources()


if __name__ == '__main__':
    main()
