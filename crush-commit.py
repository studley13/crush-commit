#!/usr/bin/env python

"""
This uses HMAC as the basis of a commitment protocol.
The person with the crush creates a string with their
name and an identifier of their crush. They then generate
a key, preferably a 256-bit random value, and keep this
secret. They then publish the format of the string along
with the result of the string with the identifier from
the HMAC using the secret key.

This process allows for a person to commit to a crush and
then they can reveal who their crush is at a later date
along with the secret key. The combination of the two can
be verified by replicating the hash process. This allows any
third party to verify that the person's revealed crush was
the same as identified in the original instance where the
hash was created.

The use of HMAC ensures that the identifier cannot be
brute-forced to reveal the person's crush and the process
ensures that the person doesn't lie about their crush at
a later date. The string ensures that the person cannot lie
by generating multiple keys to validate different secrets
to the same result.

To commit to a crush, use the commit command and publicise
the commitment file.
To reveal a crush, publicise the key file.
To check a revealed crush, use the check command with the
publicised commitment and key.
"""

from sys      import argv, stdin, stdout
from textwrap import dedent
from os       import urandom
from json     import load as jsonLoad, dump as jsonSave
from hashlib  import sha256

OPAD_BYTE  = chr(0x5C)
IPAD_BYTE  = chr(0x36)
BLOCK_SIZE = 256 / 8

def printHelp():
    print dedent("""\
    Crush Commitment
    Usage
    {0} [command] key commitment

    Commands
        commit  interactively create a commitment
        check   check a revealed commitment

    Parameters
        key         file where the key and secret are stored
        commitment  file where the commitment is stored

    About
    {1}""").format(argv[0], __doc__)

def commit(keyPath, commitPath):
    # Create dictionaries for the commitment and key data
    commitment = {}
    secret     = {}

    # Generate 256-bit Key
    key           = urandom(BLOCK_SIZE)
    secret["key"] = key.encode('hex')

    # Get the format string for the message
    commitment["format"] = raw_input(dedent("""\
        Enter a format string that will be used for the commitment.
        Include a single {} where the secret value will appear.
    """))

    # Get the secret value
    secret["value"] = raw_input(dedent("""\
        \nEnter the secret value to be placed into the string.
    """))

    # Get the HMAC
    message            = commitment["format"].format(secret["value"])
    commitment["hmac"] = hmac(message, key).encode('hex')

    jsonSave(commitment, file(commitPath, 'w'), indent=2)
    jsonSave(secret,     file(keyPath,    'w'), indent=2)


def check(keyPath, commitPath):
    # load the commitment and keys from file
    commitment = jsonLoad(file(commitPath, 'r'))
    secret     = jsonLoad(file(keyPath,    'r'))

    # Load the key, message and HMAC
    key      = secret["key"].decode('hex')
    authCode = commitment["hmac"].decode('hex')
    message  = commitment["format"].format(secret["value"])

    print "Testing message:\n    {}".format(message)
    print "Given key:       {}".format(secret["key"])
    print "Commit HMAC:     {}".format(commitment["hmac"])

    testCode = hmac(message, key)

    print "Calculated HMAC: {}".format(testCode.encode('hex'))

    if testCode == authCode:
        print "Message check PASSED"
    else:
        print "Message check FAILED"

def hmac(message, key):
    """
    HMAC algorithm as described by https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
    """
    # Convert message to bytes
    message = bytes(message.encode('utf-8'))

    # Pad key (Should be block size anyway
    if (len(key) < BLOCK_SIZE):
        key += chr(0x00) * (BLOCK_SIZE - len(key))

    oKeyPad = xorBytes((OPAD_BYTE * BLOCK_SIZE), key)
    iKeyPad = xorBytes((IPAD_BYTE * BLOCK_SIZE), key)

    # Hash the message with the key
    innerHash = sha256(iKeyPad + message).digest()
    outerHash = sha256(oKeyPad + message).digest()

    return outerHash

def xorBytes(aBytes, bBytes):
    """
    XORs two byte arrays up to the length of the shortest
    """
    result = bytes()
    length = min(len(aBytes), len(bBytes))
    for i in xrange(length):
        result += chr(ord(aBytes[i]) ^ ord(bBytes[i]))
    return result

if __name__ == "__main__":
    if len(argv) != 4:
        printHelp()
    else:
        command    = argv[1]
        keyPath    = argv[2]
        commitPath = argv[3]

        if (command == "commit"):
            commit(keyPath, commitPath)
        elif (command == "check"):
            check(keyPath, commitPath)
        else:
            printHelp()
