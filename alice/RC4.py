from secrets import token_hex
import codecs

# Global modulo value of 256 which is max bytes length
MOD = 256

# Implementation Step 1 - Initialising the character array
def initialise_state_array():
    S = []
    for i in range(MOD):
        S.append(i)
    return S


# Implementation Step 2 - KSA algorithm
def KSA(key):
    key_len = len(key)      # Get key length
    S = initialise_state_array() # Initialise state array to length of key

    j = 0
    for i in range(MOD):
        j = (j + S[i] + key[i % key_len]) % MOD
        S[i], S[j] = S[j], S[i]

    return S


# Implementation Step 3 - Pseudo Random Generation Algorithm
def PRGA(S):
    i = 0
    j = 0

    while True:
        i = (i + 1) % MOD   # Scramble i for use in incrementing j with
        j = (j + S[i]) % MOD  # j+S[i] % 256

        S[i], S[j] = S[j], S[i] # Swap values
        K = S[(S[i] + S[j]) % MOD]  # Our yield value
        yield K


# Wrapper function for process of step 4
def get_key_stream(key):
    S = KSA(key)
    return PRGA(S)


def encryption_logic(key, text):

    # Convert from hex to utf-8
    key = codecs.decode(key, 'hex_codec')
    key = [c for c in key]

    # Generate object of keystream using KSA and PRGA
    key_stream = get_key_stream(key)

    res = []
    for c in text:
        val = ("%02X" % (c ^ next(key_stream))) # XOR and convert to hex
        res.append(val) # Append to result

    return ''.join(res) # Cast as strings


def encrypt(key, plaintext):
    # key is key used in encryption process, received as hex string
    # plaintext is the string we encrypt.

    # encryption_logic expects the plaintext to be converted to a list of
    # decimal values converted to the ascii decimal values from each character
    # in the string

    plaintext = [ord(c) for c in plaintext]
    return encryption_logic(key, plaintext)


def decrypt(key, ciphertext):
    ciphertext = codecs.decode(ciphertext, 'hex_codec')
    res = encryption_logic(key, ciphertext)
    return codecs.decode(res, 'hex_codec').decode('utf-8')
