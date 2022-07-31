---
title: TFCCTF writeup
author: kanon
date: 2022-07-31 19:00:00 +0900
# date: 2022-05-26 8:00:00 +0900
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

息抜きに...
cryptoctfが重すぎた...

てか、そろそろfirst bloodをとりたいすね...
![Desktop View](/assets/img/ctf/TFCCTF/1.png)




## EXCLUSIVE_ORACLE [75 solve]

繋いで適当な値を入れまくってみると、返り値が80文字以上増えなくなる。
よって、flagは半分の40文字と推測でき、入力値が40文字で、flagが40文字で共通鍵暗号的に何ができるかというとxorかなぁと...
keyを復元し、flagも復元するとフラグが取れる

いやこの問題辛くない????え、そうでもない、、そうですか。。。

### solve

```python
from pwn import *
from Crypto.Util.number import *



io = remote( "01.linux.challenges.ctf.thefewchosen.com" ,54784)
io.recvuntil(b"> ")
io.sendline(b"1"*40)
ret = eval(io.recvline(None).decode())

key = bytes_to_long(ret[:40])^bytes_to_long(b"1"*40)
print(long_to_bytes(bytes_to_long(ret[40:])^key))
#TFCCTF{wh4t's_th3_w0rld_w1th0u7_3n1gm4?}
```


## TRAIN_TO_PADDINGTON [132 solves]

### chall

```python
import os

BLOCK_SIZE = 16
FLAG = b'|||REDACTED|||'


def pad_pt(pt):
    amount_padding = 16 if (16 - len(pt) % 16) == 0 else 16 - len(pt) % 16
    return pt + (b'\x3f' * amount_padding)


pt = pad_pt(FLAG)
key = os.urandom(BLOCK_SIZE)

ct = b''

j = 0
for i in range(len(pt)):
    ct += (key[j] ^ pt[i]).to_bytes(1, 'big')
    j += 1
    j %= 16

with open('output.txt', 'w') as f:
    f.write(ct.hex())
```

### solve

まあ普通のxorの問題で、先頭と後ろでそれぞれ TFCCTF{ と\x3f*16 でxor取って出てきた値が被っていれば簡単に復元できるから被りがいいなぁとか思っていたら普通に被ってたので簡単にkeyが手に入った。このkeyを使って復元しておしまい!

```python
from Crypto.Util.number import *
from Crypto.Util.strxor import strxor

ct = bytes.fromhex("b4b55c3ee34fac488ebeda573ab1f974bf9b2b0ee865e45a92d2f14b7bdabb6ed4872e4dd974e803d9b2ba1c77baf725")

BLOCK_SIZE = 16

cts = []
for i in range(len(ct)//16):
    cts.append(ct[i*16:(i+1)*16])

flag = b"TFCCTF{"
len = len(flag)
key = strxor(cts[0][:len], flag)
key += strxor(cts[2], b"\x3f"*16)[7:]

flag = b""
for i in range(3):
    flag += strxor(cts[i], key)
print(flag)

# TFCCTF{th3_tr41n_h4s_l3ft_th3_st4t10n}

```

## ADMIN PANEL

### chall

```python
import os
import random

from Crypto.Cipher import AES

KEY = os.urandom(16)
PASSWORD = os.urandom(16)
FLAG = os.getenv('FLAG')

menu = """========================
1. Access Flag
2. Change Password
========================"""


def xor(byte, bytes_second):
    d = b''
    for i in range(len(bytes_second)):
        d += bytes([byte ^ bytes_second[i]])
    return d


def decrypt(ciphertext):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(KEY, AES.MODE_ECB)
    pt = b''
    state = iv
    for i in range(len(ct)):
        b = cipher.encrypt(state)[0]
        c = b ^ ct[i]
        pt += bytes([c])
        print(b,c,pt)
        state = state[1:] + bytes([ct[i]])
    return pt


if __name__ == "__main__":
    while True:
        print(menu)
        option = int(input("> "))
        if option == 1:
            password = bytes.fromhex(input("Password > "))
            if password == PASSWORD:
                print(FLAG)
                exit(0)
            else:
                print("Wrong password!")
                continue
        elif option == 2:
            token = input("Token > ")
            if len(token) != 64:
                print("Wrong length!")
                continue
            hex_token = bytes.fromhex(token)
            # r_byte = random.randbytes(1)
            r_byte = os.urandom(1)
            print(f"XORing with: {r_byte.hex()}")
            xorred = xor(r_byte[0], hex_token)
            PASSWORD = decrypt(xorred)

```

### solve

初手適当に手元で2*64代入したら初めのバイト以外全てのバイト列が同じものが出てきた...
何も考えずにAccess Flagで初めの値のブルートフォースで終わり。


はい、ちゃんとやります。
decrypt関数において1回目のAESでの平文にあたるものはciphertext[:16]で、2回目のAESでの平文にあたるものはciphertext[1:17]とi回目の平文はciphertext[i-1:15+i]となる。今回はこれの値を一定にすると$$c$$の値も一定になりすごーくうれしい(PASSWORDの文字列が一定の文字種が制限できる)

```python
from pwn import *
from Crypto.Util.number import *
from tqdm import tqdm

# io = process("./main.py")
io = remote("01.linux.challenges.ctf.thefewchosen.com", 54928)

io.recvuntil(b"> ")
io.sendline(b"2")
io.recvuntil(b"> ")
io.sendline(b"2"*64)


for i in tqdm(range(256)):
    io.recvuntil(b"> ")
    io.sendline(b"1")
    # print(io.recvuntil(b"> "))
    # print((long_to_bytes(1)*16).hex())
    io.sendline((long_to_bytes(i)*16).hex().encode())
    tmp = io.recvline()
    if b"{" in tmp:
        print(tmp)
        exit()
# TFCCTF{l0g0n_z3r0_w1th_3xtr4_st3ps!}
```

## ADMIN PANEL BUT HARDER　[78 solves]

### chall

```python
import os
import random

from Crypto.Cipher import AES

KEY = os.urandom(16)
PASSWORD = os.urandom(16)
FLAG = os.getenv('FLAG')

menu = """========================
1. Access Flag
2. Change Password
========================"""


def xor(bytes_first, bytes_second):
    d = b''
    for i in range(len(bytes_second)):
        d += bytes([bytes_first[i] ^ bytes_second[i]])
    return d


def decrypt(ciphertext):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(KEY, AES.MODE_ECB)
    pt = b''
    state = iv
    for i in range(len(ct)):
        b = cipher.encrypt(state)[0]
        c = b ^ ct[i]
        pt += bytes([c])
        state = state[1:] + bytes([ct[i]])
    return pt


if __name__ == "__main__":
    while True:
        print(menu)
        option = int(input("> "))
        if option == 1:
            password = bytes.fromhex(input("Password > "))
            if password == PASSWORD:
                print(FLAG)
                exit(0)
            else:
                print("Wrong password!")
                continue
        elif option == 2:
            token = input("Token > ")
            if len(token) != 64:
                print("Wrong length!")
                continue
            hex_token = bytes.fromhex(token)
            r_bytes = random.randbytes(32)
            print(f"XORing with: {r_bytes.hex()}")
            xorred = xor(r_bytes, hex_token)
            PASSWORD = decrypt(xorred)

```

### solve

ADMIN PANELから変化した部分はChange Passwordの乱数の部分が増加した。これでは一定値に定めるのが極めてしんどい。。
なので、Change Passwordで乱数の値が返ってくることを利用して乱数予測を行う!
帰ってくる乱数は32bytesより約80回程度集めれば乱数予測が可能となる。あとはADMIN PANELと同じ

```python
import random
from mt19937predictor import MT19937Predictor
from pwn import *
from Crypto.Util.number import *
from tqdm import tqdm

# io = process("./main.py")
io = remote("01.linux.challenges.ctf.thefewchosen.com", 55172)

def xor(bytes_first, bytes_second):
    d = b''
    for i in range(len(bytes_second)):
        d += bytes([bytes_first[i] ^ bytes_second[i]])
    return d


predictor = MT19937Predictor()
for _ in tqdm(range(120)):
    io.recvuntil(b"> ")
    io.sendline(b"2")
    io.recvuntil(b"> ")
    io.sendline(b"2"*64)
    x = bytes.fromhex(io.recvline(None).decode().split(": ")[1])
    # print(x)
    predictor.setrandbits(int.from_bytes(x, byteorder='little'), 8*32)

next_rnd = predictor.getrandbits(8*32).to_bytes(32, 'little')
io.recvuntil(b"> ")
io.sendline(b"2")
io.recvuntil(b"> ")
msg = xor(b"2"*64 ,next_rnd)
io.sendline(msg.hex().encode())
ret = bytes.fromhex(io.recvline(None).decode().split(": ")[1])
# print(ret,next_rnd, long_to_bytes(tst))
assert ret== next_rnd
print("[+] YES!!!!! find seed ")


# part2 
for i in tqdm(range(256)):
    io.recvuntil(b"> ")
    io.sendline(b"1")
    # print(io.recvuntil(b"> "))
    # print((long_to_bytes(1)*16).hex())
    io.sendline((long_to_bytes(i)*16).hex().encode())
    tmp = io.recvline()
    if b"{" in tmp:
        print(tmp)
        exit()
# TFCCTF{n0_th3_fl4g_1s_n0t_th3_0ld_0n3_plus-Th3-w0rd_h4rd3r!}
```


## ADMIN PANEL BUT HARDER FIXED　[50 solves ・56 solves]

### chall

```python
import os
import random

from Crypto.Cipher import AES

KEY = os.urandom(16)
PASSWORD = os.urandom(16)
FLAG = os.getenv('FLAG')

menu = """========================
1. Access Flag
2. Change Password
========================"""


def xor(bytes_first, bytes_second):
    d = b''
    for i in range(len(bytes_second)):
        d += bytes([bytes_first[i] ^ bytes_second[i]])
    return d


def decrypt(ciphertext):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(KEY, AES.MODE_ECB)
    pt = b''
    state = iv
    for i in range(len(ct)):
        b = cipher.encrypt(state)[0]
        c = b ^ ct[i]
        pt += bytes([c])
        state = state[1:] + bytes([ct[i]])
    return pt


if __name__ == "__main__":
    while True:
        print(menu)
        option = int(input("> "))
        if option == 1:
            password = bytes.fromhex(input("Password > "))
            if password == PASSWORD:
                print(FLAG)
                exit(0)
            else:
                print("Wrong password!")
                continue
        elif option == 2:
            token = input("Token > ").strip()
            if len(token) != 64:
                print("Wrong length!")
                continue
            hex_token = bytes.fromhex(token)
            r_bytes = random.randbytes(32)
            print(f"XORing with: {r_bytes.hex()}")
            xorred = xor(r_bytes, hex_token)
            PASSWORD = decrypt(xorred)

```

### solve

非想定解があったみたいだけどADMIN PANEL BUT HARDERで作った解法には影響なかったので、そのままlet's go!!

```python
import random
from mt19937predictor import MT19937Predictor
from pwn import *
from Crypto.Util.number import *
from tqdm import tqdm

# io = process("./main.py")
io = remote("01.linux.challenges.ctf.thefewchosen.com", 55225)

def xor(bytes_first, bytes_second):
    d = b''
    for i in range(len(bytes_second)):
        d += bytes([bytes_first[i] ^ bytes_second[i]])
    return d


predictor = MT19937Predictor()
for _ in tqdm(range(120)):
    io.recvuntil(b"> ")
    io.sendline(b"2")
    io.recvuntil(b"> ")
    io.sendline(b"2"*64)
    x = bytes.fromhex(io.recvline(None).decode().split(": ")[1])
    # print(x)
    predictor.setrandbits(int.from_bytes(x, byteorder='little'), 8*32)

next_rnd = predictor.getrandbits(8*32).to_bytes(32, 'little')
io.recvuntil(b"> ")
io.sendline(b"2")
io.recvuntil(b"> ")
msg = xor(b"2"*64 ,next_rnd)
io.sendline(msg.hex().encode())
ret = bytes.fromhex(io.recvline(None).decode().split(": ")[1])
# print(ret,next_rnd, long_to_bytes(tst))
assert ret== next_rnd
print("[+] YES!!!!! find seed ")

# part2 
for i in tqdm(range(256)):
    io.recvuntil(b"> ")
    io.sendline(b"1")
    # print(io.recvuntil(b"> "))
    # print((long_to_bytes(1)*16).hex())
    io.sendline((long_to_bytes(i)*16).hex().encode())
    tmp = io.recvline()
    if b"{" in tmp:
        print(tmp)
        exit()
# TFCCTF{4pp4r3ntly_sp4ces_br34ks_th3_0ld_0ne}
```


