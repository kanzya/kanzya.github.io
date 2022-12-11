---
title: Hero CTF v4 2022 writeup
author: kanon
date: 2022-05-29 23:00:00 +0900
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

息抜きに
ただ、cryptoが少なくて残念...


##  \[crypto\] Poly321 

## chall

```python
#!/usr/bin/env python3


FLAG = "****************************"

enc = []
for c in FLAG:
    v = ord(c)

    enc.append(
        v + pow(v, 2) + pow(v, 3)
    )

print(enc)

"""
$ python3 encrypt.py
[378504, 1040603, 1494654, 1380063, 1876119, 1574468, 1135784, 1168755, 1534215, 866495, 1168755, 1534215, 866495, 1657074, 1040603, 1494654, 1786323, 866495, 1699439, 1040603, 922179, 1236599, 866495, 1040603, 1343210, 980199, 1494654, 1786323, 1417584, 1574468, 1168755, 1380063, 1343210, 866495, 188499, 127550, 178808, 135303, 151739, 127550, 112944, 178808, 1968875]
"""
```
ただの多項式だからsageに解かせて終わり

## solve

```python
from Crypto.Util.number import *
from sage.all import *
cts = [378504, 1040603, 1494654, 1380063, 1876119, 1574468, 1135784, 1168755, 1534215, 866495, 1168755, 1534215, 866495, 1657074, 1040603, 1494654, 1786323, 866495, 1699439, 1040603, 922179, 1236599, 866495, 1040603, 1343210, 980199, 1494654, 1786323, 1417584, 1574468, 1168755, 1380063, 1343210, 866495, 188499, 127550, 178808, 135303, 151739, 127550, 112944, 178808, 1968875]

for ct in cts:
    var("v")
    f =  v + v**2+v**3-ct
    print(chr(int(str(solve(f,v)[2]).replace("v == ",""))),end="")

# Hero{this_is_very_weak_encryption_92835208}
```


##  \[crypto\] The oracle's apprentice
## chall

```python
#!/usr/bin/env python3
from Crypto.Util.number import getStrongPrime, bytes_to_long
import random

FLAG = open('flag.txt','rb').read()

encrypt = lambda m: pow(m, e, n)
decrypt = lambda c: pow(c, d, n)

e = random.randrange(3, 65537, 2)
p = getStrongPrime(1024, e=e)
q = getStrongPrime(1024, e=e)

n = p * q
φ = (p-1) * (q-1)

d = pow(e, -1, φ)

c = encrypt(bytes_to_long(FLAG))

#print(f"{n=}")
#print(f"{e=}")
print(f"{c=}")

for _ in range(3):
     t = int(input("c="))
     print(decrypt(t)) if c != t else None

```

体の準同型の性質を利用する
$$(a*b)^e=a^e*b^e$$

ここで、1回目に送信するものを$$c1$$,1回目に受信するものを$$t1$$と置く

1. $$n$$の復元 $$c1=-1 \ mod \ (n) ⇒ t1=n-1 \ mod \ (n)$$
2. $$2^d$$を求める $$c2=2\ mod\ (n) ⇒ t2=2^d \ mod \ (n)$$　
3. $$(2*ct)^d$$を求める $$c3=2*ct \ mod \ (n) ⇒ t3=(2*ct)^d \ mod \ (n)$$


最後に
$$m = t3*t2^{-1} \ mod \ (n)$$で復元できる

## solve

```python
from pwn import *
from Crypto.Util.number import *

io =  remote("crypto.heroctf.fr",9000)

c = int(io.recvline(None).decode().replace("c=",""))

io.recvuntil(b"c=")
io.sendline(b"-1")
n = int(io.recvline(None).decode())+1

io.recvuntil(b"c=")
io.sendline(b"2")
d2 = int(io.recvline(None).decode())

io.recvuntil(b"c=")
io.sendline(str(2*c).encode())
c2 = int(io.recvline(None).decode())

print(long_to_bytes((c2*pow(d2,-1,n))%n))

# Hero{m4ybe_le4ving_the_1nt3rn_run_th3_plac3_wasnt_a_g00d_id3a}

```


