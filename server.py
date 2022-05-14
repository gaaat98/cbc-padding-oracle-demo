#! /usr/bin/python3

import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode



FLAG = b"BE2M32IBEA{ev3ry_b1t_m0re_is_0ne_bit_t0o_many}"
HOST = "127.0.0.1"
PORT = 31337

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        while True:
            conn, _ = s.accept()
            KEY = get_random_bytes(16)
            cipher = AES.new(KEY, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(FLAG, AES.block_size))
            ct = b64encode(ct_bytes).decode('utf-8')
            iv = b64encode(cipher.iv).decode('utf-8')

            conn.sendall(bytes(f"Encrypted flag is: {ct}\n\n", 'utf-8'))
            conn.sendall(bytes(f"IV is: {iv}\n\n", 'utf-8'))
            while True:
                try:
                    conn.sendall(b"Give me b64encoded ct to decrypt: ")
                    target = b64decode(conn.recv(1024).strip())
                except:
                    conn.close()
                    break

                t = AES.new(KEY, AES.MODE_CBC, cipher.iv)
                pt = t.decrypt(target)
                try:
                    unpad(pt, AES.block_size)
                    conn.sendall(b"Padding is correct.\n")
                except:
                    conn.sendall(b"Wrong padding.\n")







if __name__ == "__main__":
    main()