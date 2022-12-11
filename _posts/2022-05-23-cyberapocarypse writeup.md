---
title: cyberapocarypse 2022 writeup
author: kanon
date: 2022-05-23 11:33:00 +0800
categories: [ctf,writeup]
tags: [ctf,cryptography,writeup]
math: true
mermaid: true
# image:
#   path: /commons/devices-mockup.png
#   width: 800
#   height: 500
#   alt: Responsive rendering of Chirpy theme on multiple devices.
---


去年初めて参加した大会がこの大会で1問しか解けなかった。
でも、今年はcrypto 7/10解けたんで割と満足してます..


##  \[crypto\] Android-In-The-Middle [505 solve]

### chall


```python
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
import hashlib
import random
import socketserver
import signal


FLAG = "HTB{--REDACTED--}"
DEBUG_MSG = "DEBUG MSG - "
p = 0x509efab16c5e2772fa00fc180766b6e62c09bdbd65637793c70b6094f6a7bb8189172685d2bddf87564fe2a6bc596ce28867fd7bbc300fd241b8e3348df6a0b076a0b438824517e0a87c38946fa69511f4201505fca11bc08f257e7a4bb009b4f16b34b3c15ec63c55a9dac306f4daa6f4e8b31ae700eba47766d0d907e2b9633a957f19398151111a879563cbe719ddb4a4078dd4ba42ebbf15203d75a4ed3dcd126cb86937222d2ee8bddc973df44435f3f9335f062b7b68c3da300e88bf1013847af1203402a3147b6f7ddab422d29d56fc7dcb8ad7297b04ccc52f7bc5fdd90bf9e36d01902e0e16aa4c387294c1605c6859b40dad12ae28fdfd3250a2e9
g = 2


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        signal.alarm(0)
        main(self.request)


class ReusableTCPServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass


def sendMessage(s, msg):
    s.send(msg.encode())


def recieveMessage(s, msg):
    sendMessage(s, msg)
    return s.recv(4096).decode().strip()


def decrypt(encrypted, shared_secret):
    key = hashlib.md5(long_to_bytes(shared_secret)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    message = cipher.decrypt(encrypted)
    return message


def main(s):
    sendMessage(s, DEBUG_MSG + "Generating The Global DH Parameters\n")
    sendMessage(s, DEBUG_MSG + f"g = {g}, p = {p}\n")
    sendMessage(s, DEBUG_MSG + "Calculation Complete\n\n")

    sendMessage(s, DEBUG_MSG + "Generating The Public Key of CPU...\n")
    c = random.randrange(2, p - 1)
    C = pow(g, c, p)
    sendMessage(s, DEBUG_MSG + "Calculation Complete\n")
    sendMessage(s, DEBUG_MSG + "Public Key is: ???\n\n")

    M = recieveMessage(s, "Enter The Public Key of The Memory: ")

    try:
        M = int(M)
    except:
        sendMessage(s, DEBUG_MSG + "Unexpected Error Occured\n")
        exit()

    sendMessage(s, "\n" + DEBUG_MSG + "The CPU Calculates The Shared Secret\n")
    shared_secret = pow(M, c, p)
    sendMessage(s, DEBUG_MSG + "Calculation Complete\n\n")

    encrypted_sequence = recieveMessage(
        s, "Enter The Encrypted Initialization Sequence: ")

    try:
        encrypted_sequence = bytes.fromhex(encrypted_sequence)
        assert len(encrypted_sequence) % 16 == 0
    except:
        sendMessage(s, DEBUG_MSG + "Unexpected Error Occured\n")
        exit()

    sequence = decrypt(encrypted_sequence, shared_secret)

    if sequence == b"Initialization Sequence - Code 0":
        sendMessage(s, "\n" + DEBUG_MSG +
                    "Reseting The Protocol With The New Shared Key\n")
        sendMessage(s, DEBUG_MSG + f"{FLAG}")
    else:
        exit()


if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    server = ReusableTCPServer(("0.0.0.0", 1337), Handler)
    server.serve_forever()

```

### solve

典型的なAES暗号と、DHの値を一意に定めよう問題

```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
import hashlib


p = 0x509efab16c5e2772fa00fc180766b6e62c09bdbd65637793c70b6094f6a7bb8189172685d2bddf87564fe2a6bc596ce28867fd7bbc300fd241b8e3348df6a0b076a0b438824517e0a87c38946fa69511f4201505fca11bc08f257e7a4bb009b4f16b34b3c15ec63c55a9dac306f4daa6f4e8b31ae700eba47766d0d907e2b9633a957f19398151111a879563cbe719ddb4a4078dd4ba42ebbf15203d75a4ed3dcd126cb86937222d2ee8bddc973df44435f3f9335f062b7b68c3da300e88bf1013847af1203402a3147b6f7ddab422d29d56fc7dcb8ad7297b04ccc52f7bc5fdd90bf9e36d01902e0e16aa4c387294c1605c6859b40dad12ae28fdfd3250a2e9
g = 2

m = b"Initialization Sequence - Code 0"
print(isPrime(p))

def encrypt(message, shared_secret):
    key = hashlib.md5(long_to_bytes(shared_secret)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(message)
    return encrypted

print(encrypt(m, 1).hex())
# HTB{7h15_p2070c0l_15_pr0tec73d_8y_D@nb3er_c0pyr1gh7_1aws}
```


## \[crypto\] Jenny From The Block [312 solve]

### chall

```python
from hashlib import sha256
from Crypto.Util.Padding import pad, unpad
import signal
import subprocess
import socketserver
import os

allowed_commands = [b'whoami', b'ls', b'cat secret.txt', b'pwd']
BLOCK_SIZE = 32


def encrypt_block(block, secret):
    enc_block = b''
    for i in range(BLOCK_SIZE):
        val = (block[i]+secret[i]) % 256
        enc_block += bytes([val])
    return enc_block


def encrypt(msg, password):
    h = sha256(password).digest()
    print("firse_pass",h)
    if len(msg) % BLOCK_SIZE != 0:
        msg = pad(msg, BLOCK_SIZE)
    blocks = [msg[i:i+BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]
    ct = b''
    for block in blocks:
        enc_block = encrypt_block(block, h)
        h = sha256(enc_block + block).digest()
        ct += enc_block
    print("ct",ct)

    return ct.hex()


def run_command(cmd):
    if cmd in allowed_commands:
        try:
            resp = subprocess.run(
                cmd.decode().split(' '),  capture_output=True)
            output = resp.stdout
            return output
        except:
            return b'Something went wrong!\n'
    else:
        return b'Invalid command!\n'


def challenge(req):
    req.sendall(b'This is Jenny! I am the heart and soul of this spaceship.\n' +
                b'Welcome to the debug terminal. For security purposes I will encrypt any responses.')
    while True:
        req.sendall(b'\n> ')
        command = req.recv(4096).strip()
        output = run_command(command)
        response = b'Command executed: ' + command + b'\n' + output
        password = os.urandom(32)
        ct = encrypt(response, password)
        print("ct.hex",ct)
        req.sendall(ct.encode())


class incoming(socketserver.BaseRequestHandler):
    def handle(self):
        signal.alarm(30)
        req = self.request
        challenge(req)


class ReusableTCPServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass


def main():
    socketserver.TCPServer.allow_reuse_address = True
    server = ReusableTCPServer(("0.0.0.0", 1337), incoming)
    server.serve_forever()


if __name__ == "__main__":
    main()

```

### solve

"Command executed: cat secret.txt"が丁度32文字なので鍵が復元できる
これを繰り返して平文特定

```python
from hashlib import sha256
from Crypto.Util.Padding import pad, unpad
from pwn import *
from Crypto.Util.number import *

BLOCK_SIZE = 32
io = remote("159.65.49.107",31207)
# io = remote("localhost",1337)
def decrypt_block_i(block,plain):
    return  (block-plain) % 256

def search_password(ct,plain):
    secret = b""
    for i in range(BLOCK_SIZE):
        k =  decrypt_block_i(ct[i],plain[i])
        secret+=bytes([k])
    print(secret)
    return secret
    
def encrypt_block(block, secret):
    enc_block = b''
    for i in range(BLOCK_SIZE):
        val = (block[i]-secret[i]) % 256
        enc_block += bytes([val])
    return enc_block


def encrypt(msg, password):
    # h = sha256(password).digest()
    h = password
    if len(msg) % BLOCK_SIZE != 0:
        msg = pad(msg, BLOCK_SIZE)
    blocks = [msg[i:i+BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]
    ct = b''
    # for block in blocks:
    for i in range(len(blocks)):
        dec_block = encrypt_block(blocks[i], h)
        h = sha256(blocks[i] + dec_block ).digest()
        ct += dec_block

    return ct
  


def connection(io):
    io.recvuntil("> ")
    command = b'cat secret.txt'
    io.sendline(command)
    ct = bytes.fromhex(io.recvline(None).decode())
    response = b'Command executed: ' + command + b'\n' + b'Invalid command!\n'
    print("ct",ct)
    print("ct[:32]",ct[:32])
    password = search_password(ct[:32],response[:32])
    print(encrypt(ct,password))
    
connection(io)
io.close()
```

## \[crypto\] The Three-Eyed Oracle [264 solve]

### chall

```python
from tarfile import BLOCKSIZE
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random
import signal
import subprocess
import socketserver
import os
# FLAG = b''
FLAG = b'HTB{--REDACTED--}'
# prefix = random.randbytes(12)
# key = random.randbytes(16)
prefix = os.urandom(12)
key = os.urandom(16)
print(prefix)

BLOCKSIZE = 16
def encrypt(key, msg):
    msg = bytes.fromhex(msg)
    crypto = AES.new(key, AES.MODE_ECB)
    padded = pad(prefix + msg + FLAG, 16)
    # print("padded",padded)
    print("padded",[padded[i*BLOCKSIZE:(i+1)*BLOCKSIZE] for i in range(len(padded)//BLOCKSIZE)])
    print("enc",[crypto.encrypt(padded)[i*BLOCKSIZE:(i+1)*BLOCKSIZE] for i in range(len(crypto.encrypt(padded))//BLOCKSIZE)])
    return crypto.encrypt(padded).hex()


def challenge(req):
    req.sendall(b'Welcome to Klaus\'s crypto lab.\n' +
                b'It seems like there is a prefix appended to the real firmware\n' +
                b'Can you somehow extract the firmware and fix the chip?\n')
    while True:
        req.sendall(b'> ')
        # try:
        msg = req.recv(4096).decode()
        print("msg decode  ",msg)

        ct = encrypt(key, msg)
        # except:
        #     req.sendall(b'An error occurred! Please try again!')

        req.sendall(ct.encode() + b'\n')


class incoming(socketserver.BaseRequestHandler):
    def handle(self):
        signal.alarm(1500)
        req = self.request
        challenge(req)


class ReusableTCPServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass


def main():
    socketserver.TCPServer.allow_reuse_address = True
    server = ReusableTCPServer(("0.0.0.0", 1337), incoming)
    server.serve_forever()


if __name__ == "__main__":
    main()

```

AES ECBのplaintext recovery attack
詳しくはggってもらって

### solve

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import *
from tqdm import tqdm
import random

from pwn import *

io = remote("134.209.29.182",30681)
# io = remote("localhost",1337)
BLOCKSIZE = 16
PTSIZE = 32

def send_m(m):
        
    io.recvuntil(b"> ")
    # print("send_m",(b"1"*4+m).hex().encode())
    io.sendline((b"a"*4+m).hex().encode())
    re = bytes.fromhex(io.recvline(None).decode())
    return [re[i*BLOCKSIZE:(i+1)*BLOCKSIZE] for i in range(len(re)//BLOCKSIZE)]

def plaintxt_recavary():
    PTSIZE = 9
    print("PTSIZE",PTSIZE)
    # list
    m = b""
    for i in range(1,PTSIZE):
        target = send_m(b"0"*(BLOCKSIZE-i))[1]
        
        for k in tqdm(range(70,0x100)):
            a = b"0"*(BLOCKSIZE-i)+m+bytes([k])
            tmp = send_m(a)[1]    
            if tmp== target:
                m =m + bytes([k])
                break
    return m


print(plaintxt_recavary())
```

## \[crypto\] How The Columns Have Turned [239 solve]

### chall

```python
import os


with open('super_secret_messages.txt', 'r') as f:
    SUPER_SECRET_MESSAGES = [msg.strip() for msg in f.readlines()]


def deriveKey(key):
    derived_key = []

    for i, char in enumerate(key):
        previous_letters = key[:i]
        new_number = 1
        for j, previous_char in enumerate(previous_letters):
            if previous_char > char:
                derived_key[j] += 1
            else:
                new_number += 1
        derived_key.append(new_number)
    return derived_key


def transpose(array):
    return [row for row in map(list, zip(*array))]


def flatten(array):
    return "".join([i for sub in array for i in sub])


def twistedColumnarEncrypt(pt, key):
    derived_key = deriveKey(key)
    print(derived_key)

    width = len(key)

    blocks = [pt[i:i + width] for i in range(0, len(pt), width)]
    print(blocks)
    blocks = transpose(blocks)
    print("blocks",blocks)
    print(derived_key.index(2))
    for i in range(width):
        print(derived_key.index(i + 1),blocks[derived_key.index(i + 1)])
    ct = [blocks[derived_key.index(i + 1)][::-1] for i in range(width)]
    print(ct)
    ct = flatten(ct)
    print(ct)
    return ct



class PRNG:
    def __init__(self, seed):
        self.p = 0x2ea250216d705
        self.a = self.p
        # self.b = int.from_bytes(os.urandom(16), 'big')
        self.b = 729513912306026
        self.rn = seed

    def next(self):
        self.rn = ((self.a * self.rn) + self.b) % self.p
        return self.rn


def main():
    seed = int.from_bytes(os.urandom(16), 'big')
    rng = PRNG(seed)

    cts = ""

    for message in SUPER_SECRET_MESSAGES:
        key = str(rng.next())
        ct = twistedColumnarEncrypt(message, key)
        cts += ct + "\n"

    with open('encrypted_messages.txt', 'w') as f:
        f.write(cts)

    dialog = "Miyuki says:\n"
    dialog += "Klaus it's your time to sign!\n"
    dialog += "All we have is the last key of this wierd encryption scheme.\n"
    dialog += "Please do your magic, we need to gather more information if we want to defeat Draeger.\n"
    dialog += f"The key is: {str(key)}\n"

    with open('dialog.txt', 'w') as f:
        f.write(dialog)


if __name__ == '__main__':
    main()

```

### solve

PNRGかと思いきや$$a=p$$よりnext関数の出力値は$$b$$固定になり関係なくなる
あとはブロック暗号を元に戻していくだけ

```python
key = 729513912306026
import os


class PRNG:
    def __init__(self, seed):
        self.p = 0x2ea250216d705
        self.a = self.p
        self.b = 729513912306026
        self.rn = seed

    def next(self):
        self.rn = ((self.a * self.rn) + self.b) % self.p
        return self.rn

def deriveKey(key):
    derived_key = []
    # print("key",key)
    for i, char in enumerate(key):
        # print(" i, char", i, char)
        previous_letters = key[:i]
        new_number = 1
        for j, previous_char in enumerate(previous_letters):
            # print("i,j, previous_char ",i,j, previous_char )
            if previous_char > char:
                derived_key[j] += 1
            else:
                new_number += 1
        # print("new_number",new_number)
        # print("derived_key",derived_key)
        derived_key.append(new_number)
    return derived_key


def transpose(array):
    return [row for row in map(list, zip(*array))]


def flatten(array):
    return "".join([i for sub in array for i in sub])


def twistedColumnarEncrypt(pt, key):
    derived_key = deriveKey(key)
    print(derived_key)

    width = len(key)

    blocks = [pt[i:i + width] for i in range(0, len(pt), width)]
    print(blocks)
    blocks = transpose(blocks)
    print(blocks)
    print(derived_key.index(1))
    print(blocks[derived_key.index(1)][::-1])

    ct = [blocks[derived_key.index(i + 1)][::-1] for i in range(width)]
    print(ct)
    ct = flatten(ct)
    print(ct)
    return ct

twistedColumnarEncrypt("123456789012345543210987654321", str(key))
```

## \[crypto\] MOVs Like Jagger [107 solve]

### chall

```python
from ecdsa import ellipticcurve as ecc
from random import randint

a = -35
b = 98
p = 434252269029337012720086440207
Gx = 16378704336066569231287640165
Gy = 377857010369614774097663166640
ec_order = 434252269029337012720086440208

E = ecc.CurveFp(p, a, b)
G = ecc.Point(E, Gx, Gy, ec_order)


def generateKeyPair():
    private = randint(1, 2**64)
    public = G * private
    return(public, private)


def calculatePointsInSpace():
    Q, nQ = generateKeyPair()
    P, nP = generateKeyPair()
    return [Q, nQ, P, nP]


def checkCoordinates(data: dict) -> list:
    if data['destination_x'] == "" or data['destination_y'] == "":
        raise ValueError('Empty coordinates...')

    try:
        destination_x = int(data['destination_x'], 16)
        destination_y = int(data['destination_y'], 16)
    except:
        raise ValueError('Coordinates are not in the right format (hex)')

    return (destination_x, destination_y)


def checkDestinationPoint(data: dict, P: ecc.Point, nQ: int, E: ecc.CurveFp) -> list:
    # destination_x, destination_y = checkCoordinates(data)
    destination_x, destination_y = data
    destination_point = ecc.Point(E, destination_x, destination_y, ec_order)
    secret_point = P * nQ
    print("secret_point = P * nQ",secret_point , P , nQ)
    same_x = destination_point.x() == secret_point.x()
    same_y = destination_point.y() == secret_point.y()

    if (same_x and same_y):
        return True
    else:
        return False


if "__main__"==__name__:
    Q, nQ, P, nP = calculatePointsInSpace()
    print(Q, nQ, P, nP )
    checkDestinationPoint([Gx, Gy],P,nQ,E)
```

### solve

典型的なECCの問題。ただ、$$p$$が素数でないので因数分解を施すといい感じにばらけたのでPohlig–Hellman algorithmで解いていく

```python
from sage.all import *

#素数は小さければ小さいほうがいいが大きいものも場合によっては必要

#[s]P1 = P2
# fac = Ep.order())
def Pohlig_Hellman(P1,P2,fac):
    primes = []
    for i in range(len(fac)-1):
        primes.append(fac[i][0]**fac[i][1])
        #primes =[ 7 , 11 , 17 , 191 , 317 , 331 , 5221385621 , 5397618469 , 210071842937040101 , 637807437018177170959577732683]
    dlogs = []
    for fac in primes[:]:
        t = int(P1.order()) // int(fac)
        dlog = (t*P1).discrete_log(t*P2) #discrete_log(t*sGq, t*Gq, operation="+")
        dlogs += [dlog]
        print("factor: "+str(fac)+", Discrete Log: "+str(dlog)) #calculates discrete logarithm for each prime order
    return crt(dlogs, primes[:])


a = -35
b = 98
p = 434252269029337012720086440207
Gx = 16378704336066569231287640165
Gy = 377857010369614774097663166640
ec_order = 434252269029337012720086440208

E = EllipticCurve(GF(p),[a,b])
{"departed_x":"0x3b41ebf4c4afc44b98bc8542","departed_y":"0xd8d92015d026528a7dbc3309","present_x":"0x2f8756f6476af7a24952eb8e3","present_y":"0x1a61b777121c1d25bfd6c2f48"}

G = E(Gx,Gy)
Q = E(0x3b41ebf4c4afc44b98bc8542,0xd8d92015d026528a7dbc3309)
P = E(0x2f8756f6476af7a24952eb8e3,0x1a61b777121c1d25bfd6c2f48)
nP = Pohlig_Hellman(G,P,factor(ec_order))
print(nP,(360301137196997).bit_length())
for i in range(360301137196997):
    if ((ec_order//360301137196997)*i+nP)*G==P:
        print(i)
        break
nP = (ec_order//360301137196997)*i+nP
nQ = Pohlig_Hellman(G,Q,factor(ec_order))
print(nQ,(360301137196997).bit_length())
for i in range(360301137196997):
    if ((ec_order//360301137196997)*i+nQ)*G==Q:
        print(i)
        break
nQ=(ec_order//360301137196997)*i+nQ

print(nP*(nQ*G))

print()
```

## \[crypto\] Find Marher's Secret [70 solve]

### chall

```python
import random
import signal
import subprocess
import socketserver
import json
import os
from Crypto.Cipher import ARC4, AES
import os
import hashlib
from secret import FLAG, KEY


def encrypt(key, iv, pt):
    return ARC4.new(iv + key).encrypt(pt).hex()


def challenge(req):
    key = bytes.fromhex(KEY)
    assert(len(key) == 27)
    req.sendall(b'Connected to the cyborg\'s debugging interface\n')
    while True:
        req.sendall(
            b'\nOptions:\n1. Encrypt your text.\n2. Claim the key.\n> ')
        try:
            response = json.loads(req.recv(4096).decode())
            if response['option'] == 'encrypt':
                iv = bytes.fromhex(response['iv'])
                pt = bytes.fromhex(response['pt'])
                ct = encrypt(key, iv, pt)
                payload = {'response': 'success',
                           'pt': response['pt'], 'ct': ct}
                payload = json.dumps(payload)
                req.sendall(payload.encode())
            elif response['option'] == 'claim':
                answer = bytes.fromhex(response['key'])
                if hashlib.sha256(answer).hexdigest() == hashlib.sha256(key).hexdigest():
                    payload = {'response': 'success', 'flag': FLAG}
                    payload = json.dumps(payload)
                    req.sendall(payload.encode())
                else:
                    payload = {'response': 'fail',
                               'message': 'Better luck next time.'}
                    payload = json.dumps(payload)
                    req.sendall(payload.encode())

            else:
                payload = {'response': 'error', 'message': 'Invalid option!'}
                payload = json.dumps(payload)
                req.sendall(payload.encode())
        except Exception as e:
            payload = json.dumps(
                {'response': 'error', 'message': 'An error occured!'})
            req.sendall(payload.encode())
            return


class incoming(socketserver.BaseRequestHandler):
    def handle(self):
        signal.alarm(6000)
        req = self.request
        challenge(req)


class ReusableTCPServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass


def main():
    socketserver.TCPServer.allow_reuse_address = True
    server = ReusableTCPServer(("0.0.0.0", 1337), incoming)
    server.serve_forever()


if __name__ == "__main__":
    main()

```

### solve

RC4かつオラクルが無制限に使えるのでFluhrer-Mantin-Shamir attackで終わり

```python
from Crypto.Cipher import ARC4, AES
from pwn import *
import json
from collections import Counter
from tqdm import tqdm
io = remote("157.245.33.77",32157)
io.recvuntil(b"> ")




def encrypt_oracle(iv,pt):
    # def _encrypt(self, iv, key, p):
    # return ARC4.new(iv + key).encrypt(p)
    payload = {'option': 'encrypt',
           'iv': iv.hex(),
           'pt': pt.hex()}
    # print(payload)
    payload = json.dumps(payload)
    io.sendline(payload.encode())
    a = io.recvline(None).decode()
    # print(a)
    response = json.loads(a)
    # print(response['pt'])
    # print(response['ct'])
    io.recvuntil(b"> ")
    return bytes.fromhex(response['ct'])
    

def possible_key_bit(key, c):
    s = [i for i in range(256)]
    j = 0
    for i in range(len(key)):
        j = (j + s[i] + key[i]) % 256
        tmp = s[i]
        s[i] = s[j]
        s[j] = tmp

    return (c[0] - j - s[len(key)]) % 256


def attack(encrypt_oracle, key_len):
    """
    Recovers the hidden part of an RC4 key using the Fluhrer-Mantin-Shamir attack.
    :param encrypt_oracle: the padding oracle, returns the encryption of a plaintext under a hidden key concatenated with the iv
    :param key_len: the length of the hidden part of the key
    :return: the hidden part of the key
    """
    key = bytearray([3, 255, 0])
    for a in range(key_len):
        key[0] = a + 3
        possible = Counter()
        for x in tqdm(range(256)):
            key[2] = x
            # iv ,pt
            c = encrypt_oracle(key[:3], b"\x00")
            possible[possible_key_bit(key, c)] += 1
        key.append(possible.most_common(1)[0][0])
        print(key)

    return key[3:]
# print(attack(encrypt_oracle,27))

key = b'\x1f\xec\x07\x87\xbd\x1aR\xad\xe6:7\x9a <+\xe9+\x98\x1e\xb1\x17\xda\xc4\x03N\xcc\xe0'
# def _encrypt(self, iv, key, p):
# return ARC4.new(iv + key).encrypt(p)
payload = {'option': 'claim',
        'key': key.hex()}
# print(payload)
payload = json.dumps(payload)
io.sendline(payload.encode())
a = io.recvline(None).decode()
print(a)
response = json.loads(a)
print(response['flag'])
# print(response['ct'])
io.recvuntil(b"> ")




```

## \[crypto\] Down the Rabinhole [74 solve]

### chall

```python
from Crypto.Util.number import getPrime, isPrime, bytes_to_long
from Crypto.Util.Padding import pad
import os


FLAG = b"HTB{--REDACTED--}"


def getPrimes(coefficient):
    while True:
        a = getPrime(512)
        p = 3 * coefficient * a + 2
        if isPrime(p):
            break
    while True:
        b = getPrime(512)
        q = 3 * coefficient * b + 2
        if isPrime(q):
            break
    return p, q


def encrypt(message, coefficient):
    p, q = getPrimes(coefficient)
    n = p * q

    padded_message = bytes_to_long(pad(message, 64))
    message = bytes_to_long(message)

    c1 = (message * (message + coefficient)) % n
    c2 = (padded_message * (padded_message + coefficient)) % n
    return (n, c1, c2)


def main():
    coefficient = getPrime(128)
    out = ""

    message = FLAG[0:len(FLAG)//2]
    n1, c1, c2 = encrypt(message, coefficient)
    out += f"{n1}\n{c1}\n{c2}\n"

    message = FLAG[len(FLAG)//2:]
    n2, c3, c4 = encrypt(message, coefficient)
    out += f"{n2}\n{c3}\n{c4}"

    with open("out.txt", "w") as f:
        f.write(out)


if __name__ == '__main__':
    main()

```

### solve

$$n1=(3*coff*a_{1}+2)(3*coff*b_{1}+2)$$,$$n2=(3*coff*a_2+2)(3*coff*b_2+2)$$　より$$coff = gcd(n1-4,n2-4)$$
よって$$coff$$が特定できたのでmod $$n$$ 上の二次多項式を解けば答えが出る

```python
from tqdm import tqdm
from Crypto.Util.Padding import pad
from Crypto.Util.number import *
n1 = 59695566410375916085091065597867624599396247120105936423853186912270957035981683790353782357813780840261434564512137529316306287245132306537487688075992115491809442873176686026221661043777720872604111654524551850568278941757944240802222861051514726510684250078771979880364039814240006038057748087210740783689350438039317498789505078530402846140787188830971536805605748267334628057592989
c1 = 206131769237721955001530863959688756686125485413899261197125641745745636359058664398433013356663394210624150086689905532
c2 = 14350341133918883930676906390648724486852266960811870561648194176794020698141189777337348951219934072588842789694987397861496993878758159916334335632468891342228755755695273096621152247970509517996580512069034691932835017774636881861331636331496873041705094768329156701838193429109420730982051593645140188946
n2 = 56438641309774959123579452414864548345708278641778632906871133633348990457713200426806112132039095059800662176837023585166134224681069774331148738554157081531312104961252755406614635488382297434171375724135403083446853715913787796744272218693049072693460001363598351151832646947233969595478647666992523249343972394051106514947235445828889363124242280013397047951812688863313932909903047
c3 = 429546912004731012886527767254149694574730322956287028161761007271362927652041138366004560890773167255588200792979452452
c4 = 29903904396126887576044949247400308530425862142675118500848365445245957090320752747039056821346410855821626622960719507094119542088455732058232895757115241568569663893434035594991241152575495936972994239671806350060725033375704703416762794475486000391074743029264587481673930383986479738961452214727157980946




## coff part
print(gcd(n1-4,n2-4),int(gcd(n1-4,n2-4)).bit_length())

for i in range(1,1<<(int(gcd(n1-4,n2-4)).bit_length()-128)):
    if gcd(n1-4,n2-4)%i==0:
        print(i)
coff = 263063435253385937926984981365320113271

assert isPrime(coff)


# c1 = x(x+coff) mod n
# c2 = (x*1<<k+l)*(x*1<<k+l+coff) mod n

m_t = []
def search(k,N,C1,C2):
    
    l = bytes_to_long(pad(b"1"*(64-k), 64)[-1*k:])
    # print(pad(b"1"*(64-k), 64))
    # print(pad(b"1"*(64-k), 64)[-1*k:])
    # print(long_to_bytes(bytes_to_long(b"1"*(64-k))<<(8*k)))
    # print(l)
    # exit()
    
    padding = 1<<(8*k)
    #c1
    C1 = C1
    C1_coff = coff
    
    # #c2
    C2 = (C2-l*(l+coff))*pow(padding,-2,N)
    C2_coff = (2*l+coff)*pow(padding,-1,N)
    
    #C2-C1 = (C2_coff-C1_coff)*m
    m = ((C2-C1)*pow(C2_coff-C1_coff,-1,N))%N
    # print(long_to_bytes(m))
    return  long_to_bytes(m)
    
for i in range(2,64):
    if b'HTB{' in search(i,n1,c1,c2):
        print(search(i,n1,c1,c2))
for i in range(2,64):
    if search(i,n2,c3,c4).endswith(b"}"):
        print(search(i,n2,c3,c4))


# 'HTB{gcd_+_2_*_R@6in_.|5_thi5_@_cro55over_epi5ode?}
```