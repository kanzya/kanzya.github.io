---
title: GDG Algiers CTF writeup
author: kanon
date: 2022-10-10 1:00:00 +0800
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


# 初めに
SEKAICTFで疲れたので息抜きに...

## \[crypto\] The_Messager 

### chall

```python
from Crypto.Util.number import bytes_to_long, getStrongPrime
from math import gcd
from flag import FLAG
from Crypto.Random import get_random_bytes



def encrypt(m):
    return pow(m,e,N)



e = 65537
p = getStrongPrime(512)
q = getStrongPrime(512)


# generate secure keys
result = 0
while (result !=1):
    p = getStrongPrime(512)
    q = getStrongPrime(512)
    result = gcd(e,(p-1)*(q-1)) 	
N = p * q

print("N = " + str(N))
print("e = " + str(e))

ct= []

for car in FLAG:
	ct.append(encrypt(car))

print("ct = "+str(ct))

```

### solve

$p,q$が512bitからなる素因数分解は結構だるいので、逆から考える。\\
フラグの文字列におけるASCIIの範囲が$0x20-0x7f$までであることを利用し1文字づつ復号しておしまい。


```python
N = 98104793775314212094769435239703971612667878931942709323496314311667226421821897454047455384364608911477616865967419199078405667657976292973268348872702988831334377069809925141829484522654208638838107410232921531587371072553811548927714437673444716295120279177952417246053452081185183736591850104338774924467
e = 65537
ct = [snipped...]


from Crypto.Util.number import bytes_to_long, getStrongPrime
from math import gcd
from Crypto.Random import get_random_bytes

m = ""
for c in ct:
    for i in range(0x20,0x7f):
        if c == pow(i,e,N):
            m+=chr(i)
            print(m)
# CyberErudites{RSA_1S_S1MPL3}
```

## \[crypto\] The Matrix

### chall

```python
import json
from os import urandom
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from sage.all import *
from Crypto.Util.number import getPrime
from random import randint

p = getPrime(64)

def read_matrix(file_name):
    data = open(file_name, 'r').read().strip()
    rows = [list(eval(row)) for row in data.splitlines()]
    return Matrix(GF(p), rows)

def encrypt(plaintext,key):
    iv = urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext,16))
    return iv,ciphertext

G = read_matrix('matrix.txt')
priv = randint(1,p-1)

pub = G**priv
key = SHA256.new(data=str(priv).encode()).digest()[:2**8]

flag = b'CyberErudites{???????????????????????????????}'
iv,encrypted_flag = encrypt(flag,key)
with open('public_key.txt', 'wb') as f:
    for i in range(N):
           f.write((str(list(pub[i])).encode())+b'\n')
json.dump({
    "iv": iv.hex(),
    "ciphertext": encrypted_flag.hex(),
    "p":str(p)
}, open('encrypted_flag.txt', 'w'))

```


### solve

正方行列における離散対数問題を解くシンプルな問題。\\
そもそもとして、離散対数問題は基本的に解くのは難関だが、ある条件下において容易化する。\\
今回の場合それに当てはまり、ジョルダン標準形を用いて簡単に行う。



ある行列$G, P$を用いて$ G = P^{-1}\*G_j\*P $というジョルダン標準形を構成する。このとき$ A = G^{priv} $は$ A = P^{-1}\*G_j^{priv}\*P $となり、$G_j$が三角行列(今回の場合は対角行列)であることを考えると$A_{-1,-1} = G_{-1,-1}^{priv} \pmod p$であることより、行列の離散対数問題は素体上の離散対数問題に落ち容易に求められる。


```python
import json
from os import urandom
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from sage.all import *
from Crypto.Util.number import getPrime
from random import randint

iv =  bytes.fromhex("c534df3e87713beace67144f85aca107")
ciphertext  =  bytes.fromhex("c843230a54cc51d7b7ce2b47b0da5f8b98a04c3baad4bdae20f3fdcb5747f81c34a6962aef330f0d244116650c4305fd")
p = 12143520799543738643

def read_matrix(file_name):
    data = open(file_name, 'r').read().strip()
    rows = [list(eval(row)) for row in data.splitlines()]
    return Matrix(GF(p), rows)

def decrypt(ct,key,iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct),16)
    return pt

_G = read_matrix('matrix.txt')
Gj, P = _G.jordan_form(transformation=True)
_pub = read_matrix("public_key.txt")
G_jordan = P.inverse()*_G*P
pub_jordan = P.inverse()*_pub*P

print(G_jordan)
print(pub_jordan)

print(discrete_log(pub_jordan[-1][-1],G_jordan[-1][-1]))
priv = 7619698002081645976
assert _G**priv == _pub
key = SHA256.new(data=str(priv).encode()).digest()[:2**8]
print(decrypt(ciphertext,key,iv))
# b'CyberErudites{Di4g0n4l1zabl3_M4tric3s_d4_b3st}'

```


## \[crypto\] Eddy


### chall

```python
from pure25519.basic import (bytes_to_clamped_scalar,scalar_to_bytes,
                             bytes_to_scalar,
                             bytes_to_element, Base)
import hashlib, binascii
import os


def H(m):
    return hashlib.sha512(m).digest()


def publickey(seed):
    # turn first half of SHA512(seed) into scalar, then into point
    assert len(seed) == 32
    a = bytes_to_clamped_scalar(H(seed)[:32])
    A = Base.scalarmult(a)
    return A.to_bytes()


def Hint(m):
    h = H(m)
    return int(binascii.hexlify(h[::-1]), 16)


def signature(m, sk, pk):
    assert len(sk) == 32  # seed
    assert len(pk) == 32
    h = H(sk[:32])
    a_bytes, inter = h[:32], h[32:]
    a = bytes_to_clamped_scalar(a_bytes)
    r = Hint(inter + m)
    R = Base.scalarmult(r)
    R_bytes = R.to_bytes()
    S = r + Hint(R_bytes + pk + m) * a
    e = Hint(R_bytes + pk + m)
    return R_bytes, S, e


def checkvalid(s, m, pk):
    if len(s) != 64: raise Exception("signature length is wrong")
    if len(pk) != 32: raise Exception("public-key length is wrong")
    R = bytes_to_element(s[:32])
    A = bytes_to_element(pk)
    S = bytes_to_scalar(s[32:])
    h = Hint(s[:32] + pk + m)
    v1 = Base.scalarmult(S)
    v2 = R.add(A.scalarmult(h))
    return v1 == v2


def create_signing_key():
    seed = os.urandom(32)
    return seed


def create_verifying_key(signing_key):
    return publickey(signing_key)

```
{: file="challenge.py" }


```python
#!/usr/bin/python3

import sys
from  challenge import *
from Crypto.Util.number import *


with open("flag.txt","r") as f:
    flag = f.read()

flag = flag.encode()
sk = create_signing_key()
pk = create_verifying_key(sk)
R_flag,S_flag,e_flag = signature(flag,sk,pk)

def start():
    print("Welcom to my singing server !")
    print("-" * 10 + "Menu" + "-" * 10)
    print("1- Sign a message with a random private key ")
    print("2- Sign a message with your private key ")
    print("3- Verify the flag")
    print("4- Quit")
    print("-" * 24)

    try:
        while True:
            c = input("> ")

            if c == '1':
                msg =input("Enter your message : ").encode()
                pk = create_verifying_key(sk)
                R,S,e = signature(msg,sk,pk)
                out = {"R":R,"S": S,"e":e}
                print(out)
            elif c == '2':
                msg = input("Enter your message : ").encode()
                privk = int(input("Enter your private key : "))
                privk = long_to_bytes(privk)
                pk =  create_verifying_key(privk)
                R, S, e = signature(msg, sk, pk)
                out = {"R": R, "S": S, "e": e}
                print(out)
            elif c == '3':
                pk = int(input("Enter your public key  : "))
                pk = long_to_bytes(pk)
                if checkvalid(R_flag+scalar_to_bytes(S_flag),flag,pk):
                    print("You are an admin, Here's your flag ", flag)
                else:
                    print("Sorry , you can't get your flag !")
                    sys.exit()


            elif c == '4':
                print("Goodbye :)")
                sys.exit()

    except Exception:
        print("System error.")
        sys.exit()

start()
```
{: file="server.py" }


### solve

oracle問題で、flagを出すためにはpkを求める必要がある。pkを求めるには、skを求める必要がある。skはランダムな値と、一見求めるのが不可能に思える。

```python
def publickey(seed):
    # turn first half of SHA512(seed) into scalar, then into point
    assert len(seed) == 32
    a = bytes_to_clamped_scalar(H(seed)[:32])
    A = Base.scalarmult(a)
    return A.to_bytes()
```
{: file="publickey(seed)" }

```python
def signature(m, sk, pk):
    assert len(sk) == 32  # seed
    assert len(pk) == 32

    --------snipped--------
```
{: file="signature(m, sk, pk)" }

publickey関数とignature関数で比較する。 publickey関数の引数seedにはskの値が入ることを考慮すればsignature関数のaはpkの値になる。よって、次はaからpkを求めればよいことになる。

```python
def signature(m, sk, pk):
    --------snipped--------
    h = H(sk[:32])
    a_bytes, inter = h[:32], h[32:]
    a = bytes_to_clamped_scalar(a_bytes)
    r = Hint(inter + m)
    R = Base.scalarmult(r)
    R_bytes = R.to_bytes()
    S = r + Hint(R_bytes + pk + m) * a
    e = Hint(R_bytes + pk + m)
    return R_bytes, S, e
```
{: file="signature(m, sk, pk)" }

signature関数の後半においてS,eが既知であることを用いればaが求まる。\\
bytes_to_clamped_scalar関数(先頭2bitが01,下位3bitは000になるようにする)を戻すものを実装する

```python
def bytes_to_clamped_scalar(s):
    # Ed25519 private keys clamp the scalar to ensure two things:
    #   1: integer value is in L/2 .. L, to avoid small-logarithm
    #      non-wraparaound
    #   2: low-order 3 bits are zero, so a small-subgroup attack won't learn
    #      any information
    # set the top two bits to 01, and the bottom three to 000
    a_unclamped = bytes_to_scalar(s)
    AND_CLAMP = (1<<254) - 1 - 7
    OR_CLAMP = (1<<254)
    a_clamped = (_unclamped & AND_CLAMP) | OR_CLAMP
    return a_clamped
```
{: file="bytes_to_clamped_scalar(s)" }

以上でpkの候補が絞り込めたので確認してflagを取って終わり。
面倒なので、候補の1つを入力してだめなら繋ぎ直した。(bruteforceでないのでok)

```python

import sys
from  challenge import *
from Crypto.Util.number import *
from pwn import *

m = "CyberErudites{"


while True:
    io = remote("crypto.chal.ctf.gdgalgiers.com" ,1000)
    # io = process(["python3","server.py"])

    print(io.recvuntil(b"> ").decode())
    io.sendline(b"1")


    pk = io.recvuntil(b": ").decode()
    io.sendline(b"12")
    # io.recvline().decode()
    tmp = io.recvline(None).decode().replace("}","").split(": ")
    print(tmp)
    R = eval(tmp[1][:-5])
    s = eval(tmp[2][:-5])
    e = eval(tmp[3])

    # print(R)
    # print(s)
    # print(e)

    a = s //e
    # print(bin(a))
    # print(s//e)
    print(a)
    # rev_bytes_to_clamped_scalar(s):
    for i in range(2**3):
        for k in range(2**2):
            pk = int(bin(k)[2:] + bin(a)[2:]+bin(i)[2:],2)
            A = Base.scalarmult(a)
            A2 = bytes_to_long(A.to_bytes())
            print(A2)
            print(io.recvuntil(b"> ").decode())
            io.sendline(b"3")
            print(io.recvuntil(b": ").decode())
            io.sendline(str(A2).encode())
            tmp = io.recvline().decode()
            print(tmp)
            if tmp.endswith(b"}") :
                print(tmp)

# CyberErudites{ed25519_Uns4f3_L1b5}
```

## \[crypto\] Nitro


### chall

```python
#!/usr/bin/sage

from sage.all import *
from nitro import Nitro

with open("flag.txt","r") as f:
    flag = f.readline()

assert len(flag)==32

def str2bin(s):
    return ''.join(bin(ord(i))[2:].zfill(8) for i in s)

def main():
    print("**********       NITRO ORCALE      **********")
    print("   Welcome to the nitro oracle   ")
    print("After getting inspired by some encryption services, i tried to built my own server")
    print("My idea is based on using polynomials to make an affine encryption")
    print("Keep in mind that i can only encrypt a specific byte each time")
    print("You can send me the position of the byte and i send the encrypted byte with the used public key ")
    N, p, q, d = 8, 2, 29, 2
    assert gcd(N, q) == 1 and gcd(p, q) == 1 and q > (6 * d + 1) * p
    cipher = Nitro(N, p, q, d)
    print("------------------------------")
    print("|           MENU         |")
    print("|   a) encrypt the ith byte     |")
    print("|   b) exit    |")
    print("------------------------------")


    while True:
        menu= input("choose an option \n")
        try:
            if  menu == "a":
                i = int(input("enter the byte index: "))
                assert i<32
                m = list(str2bin(flag[i]))
                e,h = cipher.encrypt(m)
                print(e)
                print(h)

            elif menu == "b":
                print(" Good Bye !! ")
                exit()

            else:
                print("Error: invalid menu option.")
                raise Exception
        except Exception as ex:
            print("\nSomething went wrong......try again?\n")



if __name__ == "__main__":
    main()


```
{: file="nitro_server.py" }


```python

from sage.all import *

class Nitro:

    f_x = None
    g_x = None
    Fp_x = None
    Fq_x = None
    hx = None
    R = None
    Rq = None
    Rp = None

    def __init__(self, N, p, q, d):
        self.N = N
        self.p = p
        self.q = q
        self.d = d

    def random_poly(self, N, d1, d2):
        coef_list = [1] * d1 + [-1] * d2 + [0] * (N - d1 - d2)
        shuffle(coef_list)
        return  coef_list

    def keygen(self):
        RR= ZZ['x']
        Cyc = RR([-1]+[0]*(self.N - 1)+[1])#x^N-1
        R = RR.quotient(Cyc)
        Rq = RR.change_ring(Integers(self.q)).quotient(Cyc)
        Rp = RR.change_ring(Integers(self.p)).quotient(Cyc)
        while True:
            try:

                f_x = R(self.random_poly(self.N, self.d + 1, self.d))
                g_x = R(self.random_poly(self.N, self.d, self.d))
                Fp_x = Rp(lift(1 / Rp(f_x)))
                Fq_x = Rq(lift(1 / Rq(f_x)))
                break
            except:
                continue

        assert Fp_x * f_x == 1 and Fq_x * f_x == 1
        h_x = Rq(Fq_x * g_x)
        self.f_x, self.g_x, self.Fp_x, self.Fq_x, self.h_x = f_x, g_x, Fp_x, Fq_x, h_x
        self.R, self.Rq, self.Rp = R, Rq, Rp

    def encrypt(self, m: list):
        self.keygen()
        r_x = self.Rq(self.random_poly(self.N, self.d, self.d))
        m_x = self.Rp(m)
        m_x = m_x.lift()
        m_x = self.Rq(m_x)
        e_x = self.Rq(self.p * self.h_x * r_x + m_x)
        return e_x.list(), self.h_x.list()

```
{: file="nitro.py" }

### solve


剰余環の問題です。まぁ、素数2つ使っているのでNTRUかとは思います。\\
暗号化方針としては、flagを1文字ずつバイナリに変換して$\mod 2$の多項式にして、$p * h_x * r_x + m_x$ で行っています。そもそもとして、多項式の次数$N$は8なので、ASCII1文字を暗号化することを考えれば$2^8$通り、$r_x$は係数が$-1,0,1$の三種類より$3^8$通りであることを考えれば全探索できる範囲であり、全探索で終わらしてしまった....

```python

from sage.all import *
from nitro import Nitro
from pwn import *
from Crypto.Util.number import *
import collections

io = remote("crypto.chal.ctf.gdgalgiers.com" ,1001)
# io = process(["python3","nitro_server.py"])

N, p, q, d = 8, 2, 29, 2


def str2bin(s):
    return ''.join(bin(ord(i))[2:].zfill(8) for i in s)


def bin2str(s):
    try:
        s = [str(i) for i in s]
        return chr(int("".join(s),2))
    except:
        return None


def all_poly( N, d1, d2):
    coef_list_lists = []
    for i in range(3**N):
        coef_list=[]
        for k in range(N):
            if i % 3 == 2:
                coef_list.append(-1)
            else:
                coef_list.append(i % 3)
            i = i // 3
        coef_list_lists.append(coef_list)
    # print(coef_list_lists)
    return  coef_list_lists

def catch(i):
    io.recvuntil(b"choose an option").decode()
    io.sendline(b"a")
    io.recvuntil(b": ")
    io.sendline(str(i).encode())
    e_x = eval( io.recvline(None).decode())
    h_x = eval(io.recvline(None).decode())
    return e_x,h_x


RR= ZZ['x']
Cyc = RR([-1]+[0]*(N - 1)+[1])#x^N-1
R = RR.quotient(Cyc)
Rq = RR.change_ring(Integers(q)).quotient(Cyc)
Rp = RR.change_ring(Integers(p)).quotient(Cyc)

flag = ""
for i in range(32):
    mss = [ [] for _ in range(3)] 
    for m in range(3):
        e_x,h_x = catch(i)
        for k,poly in enumerate(all_poly(N ,d ,d)):
            r_x = Rq(poly)
            e_x = Rq(e_x)
            h_x = Rq(h_x)
            # m_x = Rp(m)
            # m_x = m_x.lift()
            # m_x = Rq(m_x)
            mss[m].append(bin2str(Rq(-1*p * h_x * r_x + e_x).list()))
    print(collections.Counter(mss[0]+mss[1]+mss[2]).keys()[2])
print(flag)
# CyberErudites{_NTRU_LLL_4tt4ck_}

```

答え的にはLLLで解けるらしい、後でやってみます。


## \[crypto\] franklin-last-words

### chall

```python
from Crypto.Util.number import bytes_to_long, getStrongPrime
from math import gcd
from flag import FLAG
from Crypto.Random import get_random_bytes



def encrypt_message(m):
    return pow(m,e,N)


def advanced_encrypt(a,m):
	return encrypt_message(pow(a,3,N)+(m << 24))

e = 3
p = getStrongPrime(512)
q = getStrongPrime(512)


# generate secure keys
result = 0
while (result !=1):
    p = getStrongPrime(512)
    q = getStrongPrime(512)
    result = gcd(e,(p-1)*(q-1)) 	

N = p * q

print("N = " + str(N))
print("e = " + str(e))

rand = bytes_to_long(get_random_bytes(64))

ct = []
ct.append(encrypt_message(rand << 24))

for car in FLAG:
	ct.append(advanced_encrypt(car,rand))

print("ct = "+str(ct))

```

### solve

The_Messagerの難度高め?の問題\\
まぁ、名前の通り*franklin-reiter related message attack*とは思います。ですが、なんか面倒なので多項式gcdで$ r$ 出して、全探索で終わりです。
pgcdの関数は[ここから](https://willwam.me/posts/2022-07-29-diceathope-smallfortune)お借りしました。すんげ―便利

```python
N = 128704452311502431858930198880251272310127835853066867118127724648453996065794849896361864026440048456920428841973494939542251652347755395656512696329757941393301819624888067640984628166587498928291226622894829126692225620665358415985778838076183290137030890396001916620456369124216429276076622486278042629001
e = 3
ct = [21340757543584301785921441484183053451553315439245254915339588451884106542258661009436759738472587801036386643847752005362980150928908869053740830266273664899424683013780904331345502086236995074501779725358484854206059302399319323859279240268722523450455802058257892548941510959997370995292748578655762731064,
----------snipped----------
]

from Crypto.Util.number import *
e = 3

pgcd = lambda g1, g2: g1.monic() if not g2 else pgcd(g2, g1%g2)
    
P.<r> = PolynomialRing(Zmod(N))
f1 = (bytes_to_long(b"y")^3 + r)^3 -ct[2]
f2 = (bytes_to_long(b"C")^3 + r)^3 -ct[1]

re_m2 = pgcd(f1,f2)
rnd = N-re_m2[0]

m = ""

for c in ct[1:]:
    for k in range(0x20,0x7f):
        if c == pow(k^3+rnd,3,N):
            m =m+ chr(k)


print(m)
# CyberErudites{Fr4nkl1n_W3_n33d_an0th3R_S3450N_A54P}
```