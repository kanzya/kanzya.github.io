---
title: seccon beginners writeup
author: kanzya
date: 2022-06-05 14:00:00 + 0000
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

さすがに去年よりは成長したかなぁと思います…


## \[crypto\] CoughingFox (404 solve)

### chall

```python
from random import shuffle

flag = b"ctf4b{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}"

cipher = []

for i in range(len(flag)):
    f = flag[i]
    c = (f + i)**2 + i
    cipher.append(c)

shuffle(cipher)
print("cipher =", cipher)

```

### solve

多項式で計算した後に$$shuffle$$で配列の中身をランダムに入れ替えている\\
ここで、適切な$$i$$以外はrootを取る際に虚数になることを利用して総当たりで求める

```python
from Crypto.Util.number import *
from sage.all import *
import gmpy2 
cipher = [12147, 20481, 7073, 10408, 26615, 19066, 19363, 10852, 11705, 17445, 3028, 10640, 10623, 13243, 5789, 17436, 12348, 10818, 15891, 2818, 13690, 11671, 6410, 16649, 15905, 22240, 7096, 9801, 6090, 9624, 16660, 18531, 22533, 24381, 14909, 17705, 16389, 21346, 19626, 29977, 23452, 14895, 17452, 17733, 22235, 24687, 15649, 21941, 11472]

# print(gmpy2.iroot(12147,2))
for i in  range(len(cipher)):
    for k in  range(len(cipher)):
    
        if gmpy2.iroot(cipher[k]-i,2)[1]==True:
            print(chr(gmpy2.iroot(cipher[k]-i,2)[0]-i),end="")
    
# ctf4b{Hey,Fox?YouCanNotTearThatHouseDown,CanYou?}
```

## \[crypto\] PrimeParty (57 solve)

### chall

```python
from Crypto.Util.number import *
from secret import flag
from functools import reduce
from operator import mul


bits = 256
flag = bytes_to_long(flag.encode())
assert flag.bit_length() == 455

GUESTS = []


def invite(p):
    global GUESTS
    if isPrime(p):
        print("[*] We have been waiting for you!!! This way, please.")
        GUESTS.append(p)
    else:
        print("[*] I'm sorry... If you are not a Prime Number, you will not be allowed to join the party.")
    print("-*-*-*-*-*-*-*-*-*-*-*-*-")


invite(getPrime(bits))
invite(getPrime(bits))
invite(getPrime(bits))
invite(getPrime(bits))

for i in range(3):
    print("[*] Do you want to invite more guests?")
    num = int(input(" > "))
    invite(num)


n = reduce(mul, GUESTS)
e = 65537
cipher = pow(flag, e, n)

print("n =", n)
print("e =", e)
print("cipher =", cipher)

```


### solve

サーバ側で256bitの素数4つとクライアント側で3つの素数を用いてRSA暗号を行う \\
ただ、3つの素数の選び方によっては4つの素数を使わなくても復号できる場合があり、
今回の場合3つの素数の合計bitが455bitを少し超えるように設定するとクライアント側だけの素数で復号できる

```python
from traceback import print_tb
from Crypto.Util.number import *
from pwn import *
from sage.all import *
from tqdm import tqdm
bit = 160
p = []

for i in range(3):
    a = getPrime(bit)
    p.append(a)
    print("[+] prime >",a)


io = remote( "primeparty.quals.beginners.seccon.jp" ,1336)

    
io.recvuntil(b" > ")
io.sendline(str(p[0]).encode())
io.recvuntil(b" > ")
io.sendline(str(p[1]).encode())
io.recvuntil(b" > ")
io.sendline(str(p[2]).encode())


io.recvuntil(b"n = ")
n = int(io.recvline(None).decode())

io.recvuntil(b"e = ")
e = int(io.recvline(None).decode())

io.recvuntil(b"cipher = ")
ct = int(io.recvline(None).decode())

inv =(p[0]-1)*(p[1]-1)*(p[2]-1)
print("[+] inverse ",n//inv)
        
d = pow(e,-1,inv)
ct = ct%(p[0]*p[1]*p[2])

print(long_to_bytes(pow(ct,d,p[0]*p[1]*p[2])))

# ctf4b{HopefullyWeCanFindSomeCommonGroundWithEachOther!!!}
```

## \[crypto\] Command (85 solve)

### chall

```python
#! /usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import isPrime
from secret import FLAG, key
import os


def main():
    while True:
        print('----- Menu -----')
        print('1. Encrypt command')
        print('2. Execute encrypted command')
        print('3. Exit')
        select = int(input('> '))

        if select == 1:
            encrypt()
        elif select == 2:
            execute()
        elif select == 3:
            break
        else:
            pass

        print()


def encrypt():
    print('Available commands: fizzbuzz, primes, getflag')
    cmd = input('> ').encode()

    if cmd not in [b'fizzbuzz', b'primes', b'getflag']:
        print('unknown command')
        return

    if b'getflag' in cmd:
        print('this command is for admin')
        return

    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    enc = cipher.encrypt(pad(cmd, 16))
    print(f'Encrypted command: {(iv+enc).hex()}')


def execute():
    inp = bytes.fromhex(input('Encrypted command> '))
    iv, enc = inp[:16], inp[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        cmd = unpad(cipher.decrypt(enc), 16)        
        if cmd == b'fizzbuzz':
            fizzbuzz()
        elif cmd == b'primes':
            primes()
        elif cmd == b'getflag':
            getflag()
    except ValueError:
        print("pass")
        pass


def fizzbuzz():
    for i in range(1, 101):
        if i % 15 == 0:
            print('FizzBuzz')
        elif i % 3 == 0:
            print('Fizz')
        elif i % 5 == 0:
            print('Buzz')
        else:
            print(i)


def primes():
    for i in range(1, 101):
        if isPrime(i):
            print(i)


def getflag():
    print(FLAG)


if __name__ == '__main__':
    main()

```

<!-- ![img-description](/assets/img/ctf/seccon_biggner/1.png) -->
AESのCBCモードを利用してgetflagの暗号化したものを送るようにしたい\\
AESのCBCの特徴として初めの1ブロックは復号の最後にivとXOR取って平文を返すようにしている\\
これを逆手にとって任意のivを送ることで復号結果にgetflagを出すようにすればいい


### solve

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import *
from pwn import *


io = remote("command.quals.beginners.seccon.jp", 5555)

io.recvuntil(b"> ")
io.sendline(b"1")

io.recvuntil(b"> ")
io.sendline(b"fizzbuzz")
io.recvuntil(b"Encrypted command: ")
tmp = io.recvline(None)
iv,ct = int(tmp[:32],16),tmp[32:].decode()
print(tmp)
print("iv,ct",iv,ct)


mf = bytes_to_long(pad(b"fizzbuzz", 16))
mg = bytes_to_long(pad(b"getflag", 16))

new_iv = long_to_bytes(mf^iv^mg)
print(new_iv)
new_iv = new_iv.hex()
print(new_iv)




io.recvuntil(b"> ")
io.sendline(b"2")
io.recvuntil(b"Encrypted command> ") 
print(new_iv,ct)
io.sendline((new_iv+ct).encode())
io.interactive()

# ctf4b{b1tfl1pfl4ppers}
```

## \[crypto\] omni-RSA (13 solve)

### chall

```python
from Crypto.Util.number import *
# from flag import flag



p, q, r = getPrime(512), getPrime(256), getPrime(256)
n = p * q * r
phi = (p - 1) * (q - 1) * (r - 1)
e = 2003
d = inverse(e, phi)

flag = bytes_to_long(flag.encode())
cipher = pow(flag, e, n)

s = d % ((q - 1)*(r - 1)) & (2**470 - 1)

print("rq =", r % q)

print("e =", e)
print("n =", n)
print("s =", s)
print("cipher =", cipher)


```

### solve

普段のRSAに付随して$$d$$の下位469bitと$$r$$を$$q$$で割ったあまりが与えられている\\
方針として、$$d_{qr}$$は$$d$$を$$(q-1)(r-1)$$で割ったあまり、$$0 \leq k \leq e $$とすると
$$d_{qr} = d_0 * 2^{470} + s - k*(q-1)*(r-1)$$という式が成立する\\
ここで、$$q$$の大きさは256bitであることを考えると \\
$$d_{qr} \equiv s - k*(q-1)*(r-1) mod(2^{256})$$でも成立し、$$r$$を$$q$$で割ったあまりに置き換えると\\
$$d_{qr} \equiv s - k*(q-1)*(q+rq-1) mod(2^{256})$$ \\
これを満たす$$q$$のどれかが今回の問題で使われた素数$$q$$となる


```python
from Crypto.Util.number import *
from tqdm import tqdm

rq = 7062868051777431792068714233088346458853439302461253671126410604645566438638
e = 2003
n = 140735937315721299582012271948983606040515856203095488910447576031270423278798287969947290908107499639255710908946669335985101959587493331281108201956459032271521083896344745259700651329459617119839995200673938478129274453144336015573208490094867570399501781784015670585043084941769317893797657324242253119873
s = 1227151974351032983332456714998776453509045403806082930374928568863822330849014696701894272422348965090027592677317646472514367175350102138331
cipher = 82412668756220041769979914934789463246015810009718254908303314153112258034728623481105815482207815918342082933427247924956647810307951148199551543392938344763435508464036683592604350121356524208096280681304955556292679275244357522750630140768411103240567076573094418811001539712472534616918635076601402584666


def find(d0, kbits, e, n):
    X = var('X')
    for k in tqdm(range(e+1, 1, -1)):
        results = solve_mod([k*(X-1)*(X+rq-1)+1 ==e*d0 ], 2^kbits)
        for x in results:
            if int(n)%int(x[0])==0:
                print("[+] find q --------")
                print("q",x[0])
                print("------------")
                return x[0]


if __name__ == '__main__':
    # d0 = d & (2^kbits-1)
    # print ("lower %d bits (of %d bits) is given" % (kbits, nbits))

    # p = find_p(s, int(s).bit_length(), e, n)
    q = find(s,256, e, n)
    q = 108719400953000878740030929903618126158486070837750092259928673760881189657243
    
    r = rq+q
    p = n//(r*q)
    assert n == p*q*r
    print ("[+] good primes !!")
    print (long_to_bytes(pow(cipher,inverse_mod(e, (p-1)*(q-1)*(r-1)),n)))
    
    # ctf4b{GoodWork!!!YouAreTrulyOmniscientAndOmnipotent!!!} 
``` 
