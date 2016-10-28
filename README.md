# NAME

```
crush-commit
```

# DESCRIPTION
    
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

# FUNCTIONS

```python
check(keyPath, commitPath)
```
    
```python
commit(keyPath, commitPath)
```
    
```python
hmac(message, key)
```
HMAC algorithm as described by [hash-based message authentication code](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code)
    
```python
printHelp()
```
    
```python
xorBytes(aBytes, bBytes)
```
XORs two byte arrays up to the length of the shortest

