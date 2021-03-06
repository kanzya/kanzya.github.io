---
title: Access Denied CTF 2022 writeup
author: kanon
date: 2022-06-12 19:30:00 + 0000
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

最近勉強したresultantで解けたのでよかったなぁ...\\
あと、まじでそろそろctfのチームはいりたいよ...\\
気を取り直して、正解が少ない2問あげます...
(乱数予測は解けなかったorz)

## \[crypto\] MITM-2 (17 solve)

### chall

#### alice

```python
from AES import encrypt, decrypt, padding
from binascii import hexlify, unhexlify
from hashlib import md5
import os

flag = b"XXXXXX"
msg = b"here_is_my_code!"
keys = [ b'XXXXXXXXXXXXXXXX', b'XXXXXXXXXXXXXXXX' ]

g = 41899070570517490692126143234857256603477072005476801644745865627893958675820606802876173648371028044404957307185876963051595214534530501331532626624926034521316281025445575243636197258111995884364277423716373007329751928366973332463469104730271236078593527144954324116802080620822212777139186990364810367977
p = 174807157365465092731323561678,522236549173502913317875393564963123330281052524687450754910240009920154525635325209526987433833785499384204819179549544106498491589834195860008906875039418684191252537604123129659746721614402346449135195832955793815709136053198207712511838753919608894095907732099313139446299843
private_key = 0 # Alice Private Key


def main():
	public_key = pow(g, private_key, p)
	print("> Here is my public key: {}".format(public_key))
	key = int(input("> Your public key: "))

	if(key == 0 or key == 1 or key == p - 1):
		print("> Ohhh...... Weak Keys")
		exit(0)

	aes_key = md5(unhexlify(hex(pow(key, private_key, p))[2:])).digest()
	keys.append(aes_key)
	encrypted_msg = encrypt(msg, keys, b"A"*16, b"B"*16)
	encrypted_flag = encrypt(flag[:32], keys, b"A"*16, b"B"*16)
	print("> Your output: {} {}".format(hexlify(encrypted_msg), hexlify(encrypted_flag)))
if __name__ == '__main__':
	main()
```


#### bob
```python
from AES import encrypt, decrypt, padding
from binascii import hexlify, unhexlify
from hashlib import md5
import os

# Alice and Bob keys are generated by [md5(os.urandom(3)).digest() for _ in rand]

flag = b"XXXXXX" # flag
keys = [ b'XXXXXXXXXXXXXXXX', b'XXXXXXXXXXXXXXXX' ]
msg = b"thank_you_here_is_remaining_part"

g = 41899070570517490692126143234857256603477072005476801644745865627893958675820606802876173648371028044404957307185876963051595214534530501331532626624926034521316281025445575243636197258111995884364277423716373007329751928366973332463469104730271236078593527144954324116802080620822212777139186990364810367977
p = 174807157365465092731323561678522236549173502913317875393564963123330281052524687450754910240009920154525635325209526987433833785499384204819179549544106498491589834195860008906875039418684191252537604123129659746721614402346449135195832955793815709136053198207712511838753919608894095907732099313139446299843
private_key = 0 # Bob private Key

def main():
	public_key = pow(g, private_key, p)
	print("> Here is my public key: {}".format(public_key))
	key = int(input("> Your public key: "))
	
	if(key == 0 or key == 1 or key == p - 1):
		print("> Ohhh...... Weak Keys")
		exit(0)

	aes_key = md5(unhexlify(hex(pow(key, private_key, p))[2:])).digest()
	keys.append(aes_key)
	
	code = input("> Give me the code(encrypted hex): ")
	decrypted_code = decrypt(unhexlify(code), keys, b"A"*16, b"B"*16)
	if(decrypted_code[:32] == flag[:32]):
		encrypted_msg = encrypt(msg, keys, b"A"*16, b"B"*16)
		encrypted_flag = encrypt(flag[32:], keys, b"A"*16, b"B"*16)
		print("> Your output: {} {}".format(hexlify(encrypted_msg), hexlify(encrypted_flag)))
	else:
		print("> You have given the wrong code")


if __name__ == '__main__':
	main()
```

#### AES

```python
from Crypto.Cipher import AES
from binascii import hexlify, unhexlify
from hashlib import md5
import os
import signal


def get_ciphers(keys, iv1, iv2):
    return [ AES.new(keys[0], mode=AES.MODE_ECB), AES.new(keys[1], mode=AES.MODE_CBC, iv=iv1), AES.new(keys[2], mode=AES.MODE_CBC, iv=iv2) ]


def padding(m):
    return m + os.urandom(16 - (len(m) % 16))

def encrypt(m, keys, iv1, iv2):
    m = padding(m)
    ciphers = get_ciphers(keys, iv1, iv2)
    c = m
    for cipher in ciphers:
        c = cipher.encrypt(c)
    return c


def decrypt(c, keys, iv1, iv2):
    assert len(c) % 16 == 0
    ciphers = get_ciphers(keys, iv1, iv2)
    m = c
    for cipher in ciphers[::-1]:
        m = cipher.decrypt(m)
    return m
```

### solve

この問題はDH鍵共有のman-in-the-middleとAESのmeet-in-the-middleをかけ合わせた問題。\\
DH鍵共有のpartはこちらの共有鍵が$$p-1,1,0$$の場合以外に通るので$$-1$$で通過させて解決。\\
AESのpartは鍵がos.urandom(3)で決まるので$$256^3$$のうちのどれか一つなのでmeet-in-the-middleで鍵推定を行う\\
鍵がわかればAES.pyを用いてflag出して終わり

```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
from binascii import hexlify, unhexlify
from hashlib import md5
from tqdm import tqdm
from pwn import *
import os 
from AES import encrypt, decrypt, padding

p = 174807157365465092731323561678522236549173502913317875393564963123330281052524687450754910240009920154525635325209526987433833785499384204819179549544106498491589834195860008906875039418684191252537604123129659746721614402346449135195832955793815709136053198207712511838753919608894095907732099313139446299843
a_pub = 119411071723122444381767470125626227123727573250251216315907714124627930184475306091652961747380924296747933021923661790680670240155231816516457033069067832914869305822175715488571133446537348467810750635631617119618614773943953032009463487011337635599632404459399646451549811120239365019103442516813610951801
g = 41899070570517490692126143234857256603477072005476801644745865627893958675820606802876173648371028044404957307185876963051595214534530501331532626624926034521316281025445575243636197258111995884364277423716373007329751928366973332463469104730271236078593527144954324116802080620822212777139186990364810367977
# Alice and Bob keys are generated by [md5(os.urandom(3)).digest() for _ in rand]

def conection_alice(io):
    io.recvuntil(b"ey: ")
    a_pub = int(io.recvline(None).decode())

    io.recvuntil(b"key: ")
    io.sendline(str(-1).encode())

    io.recvuntil(b"Your output: ")
    a = io.recvline(None).decode().split(" ")
    encrypted_msg = bytes.fromhex( eval(a[0]).decode())
    encrypted_flag =bytes.fromhex(eval(a[1]).decode())
    io.close()
    print("[+] encrypted_msg",encrypted_msg)
    print("[+] encrypted_flag",encrypted_flag)
    return encrypted_msg,encrypted_flag

def conection_bob(io,enc):
    io.recvuntil(b"ey: ")
    a_pub = int(io.recvline(None).decode())

    io.recvuntil(b"key: ")
    io.sendline(str(-1).encode())
    
    io.recvuntil(b"hex): ")
    io.sendline(enc.hex().encode())

    io.recvuntil(b"Your output: ")
    a = io.recvline(None).decode().split(" ")
    encrypted_msg = bytes.fromhex( eval(a[0]).decode())
    encrypted_flag =bytes.fromhex(eval(a[1]).decode())
    io.close()
    print("[+] encrypted_msg",encrypted_msg)
    print("[+] encrypted_flag",encrypted_flag)
    return encrypted_msg,encrypted_flag

def MITM(encrypted_msg):
    aes_key =md5(unhexlify(hex(pow(-1, 1, p))[2:])).digest()
    # decrypt AES3
    cipher3 = AES.new(aes_key, mode=AES.MODE_CBC, iv=b"B"*16)
    encrypted_msg = cipher3.decrypt(encrypted_msg)

    # ecrypt AES1
    AES1 = []
    for key in tqdm(range(0,256^3)):
        chipher = AES.new(md5(long_to_bytes(key)).digest(), mode=AES.MODE_ECB)
        AES1.append(chipher.encrypt(a_msg))
    # decrypt AES2
    AES2 =[]
    for key in tqdm(range(0,256^3)):
        chipher2 = AES.new(md5(long_to_bytes(key)).digest(), mode=AES.MODE_CBC, iv=b"A"*16)
        AES2.append(chipher2.decrypt(encrypted_msg))


    AES3 = AES1+AES2

    same = [k for k, v in collections.Counter(AES3).items() if v > 1]
    if same!=None:
        print("[+] find meessage")
        key1 = AES1.index(same[0])
        key2 = AES2.index(same[0])
        print("[+] find key1",key1)
        print("[+] find key2",key2)
    return key1 ,key2

#----------------alice----------------------------
io = remote("34.123.4.102" ,4000)
encrypted_msg,encrypted_flag = conection_alice(io)
a_msg = b"here_is_my_code!"

key1,key2 = MITM(encrypted_msg[:16])
# key1 = 8148705
# key2 = 14049457

keys = [md5(long_to_bytes(key1)).digest(),md5(long_to_bytes(key2)).digest(),md5(unhexlify(hex(pow(-1, 1, p))[2:])).digest()]
flag1 = decrypt(encrypted_flag, keys, b"A"*16, b"B"*16)[:-16]
print("[+] flag >",flag1)

#----------------bob----------------------------

io = remote("34.123.4.102" ,8000)
encrypted_msg,encrypted_flag = conection_bob(io,encrypted_flag)

print("[+] msg >",decrypt(encrypted_msg, keys, b"A"*16, b"B"*16))
flag2 = decrypt(encrypted_flag, keys, b"A"*16, b"B"*16)[:-16]
print("[+] flag >",flag2)
print("[+] flag >",flag1+flag2)

# accessdenied{m4n_1n_th3_m1ddl3_4nd_m33t_1n_th3_m1ddl3!_931a52e4}
```



## \[crypto\] ECC (19 solve)

### chall

```python
import tinyec.ec as ec
import tinyec.registry as reg
from hashlib import sha256
from random import randint


class RNG:
    def __init__(self, seed):
        self.state = seed
    
    def next(self):
        self.state = self.state + 1
        return self.state

def hashInt(msg):
    h = sha256(msg).digest()
    return int.from_bytes(h, 'big')

def sign(msg):
    m = hashInt(msg)
    k = rand.next()
    R = k * G
    r = R.x
    s = pow(k, -1, n) * (m + r * d) % n
    return (r, s)
    
def verify(msg, sig):
    r, s = sig
    m = hashInt(msg)
    sinv = pow(s, -1, n)
    u1 = m * sinv % n
    u2 = r * sinv % n
    R_ = u1 * G + u2 * Q
    r_ = R_.x
    return r_ == r


C = reg.get_curve("secp256r1")
G = C.g
n = C.field.n
d =  int(open("flag.txt", "rb").read().hex(), 16)
Q = d * G

rand = RNG(randint(2, n-1))

# Let's sign some msgs

m1 = b"crypto means cryptography"
m2 = b"may the curve be with you"
m3 = b"the annoying fruit equation"

sig1 = sign(m1)
sig2 = sign(m2)
sig3 = sign(m3)

assert verify(m1, sig1)
assert verify(m2, sig2)
assert verify(m3, sig3)

open("out.txt", "w").write(f"{sig1 = }\n{sig2 = }\n{sig3 = }")

```

### solve

signの式が$$s_i={k_i}^{-1}(H(m_i)+r_{i}d) \ \ mod \ \ n$$であり未知の変数は$$k_i,d$$となる。\\
ここで、RNGの性質で$$k_{i+1}=k_i + 1$$となることから、未知の変数$$k_0,d$$の2変数となる。\\
なので、resultantを計算してdを求めればflagが手に入る

後、当たり前のようにグレブナー基底でも解けた...\\
本当にグレブナー基底の解ける条件考えないと...

```python
import tinyec.ec as ec
import tinyec.registry as reg
from hashlib import sha256
from random import randint
from Crypto.Util.number import *

def hashInt(msg):
    h = sha256(msg).digest()
    return int.from_bytes(h, 'big')


m0 = hashInt(b"crypto means cryptography")
m1 = hashInt(b"may the curve be with you")
m2 = hashInt(b"the annoying fruit equation")

r,s = [0,0,0],[0,0,0]
r[0],s[0] = (104643007282746168593080909181608136842069989473568245529813036758771329973363, 64857484327908680037110311008974831697501603147734264713321850573005484948766)
r[1],s[1] = (103100238141753471646305398545577342208947972057548356113817050903685018825164, 68180337315087533969740301361624519816597436690234900639676209985924490588183)
r[2],s[2] = (102982255637408147467745136566528008388200085481044044672245245459397287601125, 90628876174756318095385459486067833878236505125282311602737298420398366610196)

C = reg.get_curve("secp256r1")
G = C.g
n = C.field.n
P.<k, d> = PolynomialRing(GF(n))

def resultant(f1, f2, var):
    return Matrix(f1.sylvester_matrix(f2, var)).determinant()

poly1 = m0 + r[0]*d - s[0]*k
poly2 = m1 + r[1]*d - s[1]*(k+1)
poly12 = resultant(poly1, poly2, k)
print(long_to_bytes(poly12.univariate_polynomial().roots()[0][0]))
# b'accessdenied{ECDSA_w34k_RNG}'
```

