import os

if os.path.isfile('alice/key.pem'):
    os.remove('alice/key.pem')

if os.path.isfile('bob/alice_fingerprint.pem'):
    os.remove('bob/alice_fingerprint.pem')

if os.path.isfile('alice/pw.pem'):
    os.remove('alice/pw.pem')
