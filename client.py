#! /usr/bin/python3

import socket
import sys
from time import sleep
from base64 import b64encode, b64decode
from binascii import hexlify


HOST = "127.0.0.1"
PORT = 31337
BLOCK_LENGTH = 16

def recvuntil(s, char):
    out = b""
    while True:
        out += s.recv(1)
        if char in out:
            break
    return out

def sendAndRecv(s, out):
    o = b64encode(out)
    s.recv(1024)
    s.sendall(o+b"\n")
    res = recvuntil(s, b".")

    return b"correct" in res

def xor(a, b):
    out = b""
    for i in range(len(a)):
        out += bytes([a[i] ^ b[i]])

    return out

def iterate(s, start, decr, blk, slowmode=False):
    i = len(decr)
    values = []

    # decr ^ padding_number = value ----> value ^ decr = padding_number
    # by doing so we force the padding values we want during the xor after the decryption
    # (assuming the discovered values are correct)
    for j in range(len(decr)):
        values.append(decr[j] ^ (i+1))

    for x in range(start, 256):
        # payload contains: 0x00 * BLOCK_LENGTH-(discovered+1) + test_value + values_to_force_padding
        payload = b"\x00"*(BLOCK_LENGTH-i-1) + bytes([x]) + bytes(values)
        print(f"Payload (pad value {i+1}):\t\t{hexlify(payload).decode()}", end="\r")
        payload = payload + blk

        if slowmode:
            sleep(0.01)

        if sendAndRecv(s, payload):
            decr = bytes([x ^ (i+1)]) + decr
            break

    return decr

def getData(s):
    data = recvuntil(s, b"\n\n")
    target = data.split(b": ")[1].strip()
    target = b64decode(target)
    return target

def main():
    if "slow" in sys.argv:
        slowmode = True
    else:
        slowmode = False

    s = socket.socket()
    s.connect((HOST, PORT))

    target = getData(s)
    iv = getData(s)

    blks = [target[i:i+BLOCK_LENGTH] for i in range(0, len(target), BLOCK_LENGTH)]
    tot = [iv] + blks
    decrs = []

    print(f"Target ciphertext is: {hexlify(target).decode()}\n")
    print(f"IV is: {hexlify(iv).decode()}\n")
    print(f"Total blocks to decrypt: {len(blks)}\n\n")

    for b, blk in enumerate(blks):
        decr = b""
        for i in range(BLOCK_LENGTH):
            # xoring backwards since we're discovering values starting from the end of the block
            print(f"\033[A\033[ABlock #{b} after decryption:\t{hexlify(decr).decode():>32}", end='\n')
            try:
                o = xor(decr[::-1], tot[b][::-1])[::-1].decode()
                # to have a nice alignment with the exadecimal counterpart
                o = ' '.join(o[i:i+1] for i in range(0, len(o)))+ " "
                print(f"Block #{b} after CBC XOR:\t\t{o:>32}", end='\n')
            except:
                # in case non printable chars are present
                o = xor(decr[::-1], tot[b][::-1])[::-1]
                print(f"Block #{b} after CBC XOR:\t\t{o}", end='\n')

            test = iterate(s, 0, decr, blk, slowmode)
            # Unlikely to happen with textual data since padding bytes go from 0x0f to 0x01
            # but with binary data can happen to have a situation like: 
            # ... 0x04 0x04 0x04 0xff immediately after decryption
            # iterating we will encounter first 251 which xored with 0xff equals to 0x04 ---> this value results in a correct padding but not the one we want
            # the correct value should be 254 which xores to 0x01, successive iteration of the algorithm will not discover any value if this error is not corrected
            # this portion of code does a step back to correct the previous decrypted value
            if test == decr:
                print("\nPrevious decrypted value was incorrect! Press enter key to step back", end="\r")
                input()
                print(f"\033[A{' '*64}\033[A\033[A")
                start_x = decr[0] ^ i
                decr = iterate(s, start_x+1, decr[1:], blk, slowmode)
            else:
                decr = test
            
        print(f"\033[A\033[A{' '*64}", end="\r")
        print(f"Block #{b}: {xor(decr, tot[b])}\n\n")
        decrs.append(decr)

    print(f"\033[A\033[A{' '*64}")
    print(f"{' '*64}", end='\r')
    print("Final plaintext: ", end='')
    final = b""
    for i in range(len(decrs)):
        final += xor(decrs[i], tot[i])

    print(final)



if __name__ == "__main__":
    main()