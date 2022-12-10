---
title: shakti CTF writeup
author: kanon
date: 2022-12-11 00:00:00 +0900
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

solveが少ないものを...

CRTの使い方が面白かったので後で自分なりにいじってみます。



## [crypto] d0uble_cbc [16 solve]

### chall

```python
from Crypto.Cipher import AES  
from Crypto.Util.Padding import pad,unpad  
from Crypto.Util.strxor import strxor
from secret import key,flag ,iv
from os import *  

def encryptt(pt):  
    return (AES.new(key,AES.MODE_CBC,iv)).encrypt(pad(pt,16))   
   
def decryptt(ct):  
    if len(ct)%16 == 0:  
        return (AES.new(key,AES.MODE_CBC,iv)).decrypt(ct)  
    elif len(ct)%16 != 0:  
        return (unpad((AES.new(key,AES.MODE_CBC,iv)).decrypt(ct) , 16))                                                                                 
  
def verify_ivv(iv,iv_detected):
    if iv.hex() == iv_detected:
        print("Yooo... you are going good, move forward with some more courage")
        return True
    else:
        print("Don't lose hope buddy , you can get through this, try again ")
        return False

def sign(iv,key,message):
    try:
        cbc = AES.new(key, AES.MODE_CBC,iv)
        messageblocks = [message[i:i + 16] for i in range(0, len(message), 16)]
        tag = cbc.encrypt(messageblocks[0])
        for i in range(1,len(messageblocks)):   
            cbc1 = AES.new(key, AES.MODE_CBC,tag)
            tag = cbc1.encrypt(messageblocks[i])
        return tag.hex()
    except:
        print("\nNo padding done here !, try again ")
        exit()

 

def main():
    print("******************************Welcome to the john's CBC server************************")
    print("You really wanna get into the system? \n then search for IV ")
    print("Choose 1 option among four \n \t 1.Encrypt the plain text \n \t 2.Decrypt the ciphertext \n \t 3.feed IV \n \t 4.exit")
    op = int(input())
    if op == 1:
        print("I will provide the encrypted text for you")
        print("Input the plaintext in hex format\n")
        pt = input()
        ct = encryptt(bytes.fromhex(pt)).hex()
        print(f"cipher text for provided" , ct);
    if op == 2:
        print("I will provide the reasonable plaintext for you")
        print("Input the cipher text in bytes to decrypt")
        ct = input()
        pt = decryptt(bytes.fromhex(ct)).hex()
        print(f"decrypted text for provided" , pt);
    if op == 3:
        print("Provide reasonable IV to proceed further")
        iv_detected = input()
        verify_iv = verify_ivv(iv,iv_detected) 
        print(verify_iv)
        if verify_iv:
            print("Let me see whether you are worth enough to gain my gold coins.")
            print("To prove yourself, give me two different hex-encoded messages that could sign to the same tag.")
            print("Now press '0' to get your hex inputs signed and press 1 to submit two same messages")
            iv_detected = bytes.fromhex(iv_detected)
            x = input()
            if x == '0':
                print("Input hash encoded message:\n")
                msg = bytes.fromhex(input())
                x = sign(iv_detected,key,msg)
                print("\n Tag for your message")
                print(x)
            if x == '1':
                msg1 = bytes.fromhex(input("\nMessage #1: \n"))
                msg2 = bytes.fromhex(input("\nMessage #2: \n"))
                if(msg1 == msg2):
                    print("\nThis is not a correct way to do this, think again!!!")
                    exit()
                if(msg1 != msg2 and sign(iv_detected,key,msg1)==sign(iv_detected,key,msg2)):
                    print(flag)
                    exit()
                else:
                    print("\nOops! They don't match!...Better luck next time!")
                    exit()                
        if op==4:
            exit()          



if __name__ == '__main__':
    main()

```

### solve

$m = m_1+m_2$とし、$c_1 = enc(m_1 \oplus iv),c_2 = enc(m_2 \oplus c_1)$としておきます。ここでの$+$は文字列の結合です。

更に$m'_2 = dec(c_2)\oplus iv,m'_1 = dec(c_1) \oplus c_2$ともしておきます。

#### part1

目標 : **ivの導出**

それぞれ既知の変数は$m_1,m_2,c_1,c_2,m'_1,m'_2$の6つ。$c_1 = enc(m_1 \oplus iv),m'_1 = dec(c_1) \oplus c_2$を纏めて$dec(c1) = m_1 \oplus iv=m'_1\oplus m'_2$より$iv = m_1 \oplus m'_1\oplus c_2$で求まる

```python
from attacks.cbc.padding_oracle import attack
from pwn import *

def bxor(a,b):
    return bytes([ a_^b_ for a_,b_ in zip(a,b)])

BLOCK_SIZE = 16

m1 = b"1"*16
m2 = b"2"*16
print((m1+m2).hex())
# 3131313131313131313131313131313132323232323232323232323232323232
enc = bytes.fromhex("1ff6715f925f8101e755d865142ca76964a478eee818f9153509586f9a05133d8831c0ab6a1dc68a83cdc8754b360909")

c1 = enc[:BLOCK_SIZE]
c2 = enc[BLOCK_SIZE:BLOCK_SIZE*2]
print("ct",(c2+c1+enc[BLOCK_SIZE*2:]).hex())

plain = bytes.fromhex("6c9b2b0cd01dca6cb60589084b71f13e14ca21bea959b17b675a0a01c65b46696b4219a16a576804c24c901a9e39a444")
m1_prime = plain[BLOCK_SIZE:]
iv_cal = bxor(bxor(c2,m1_prime),m1)
print(iv_cal)
iv = b"A_happy_cbc_mode"
print(iv.hex())
```

#### part 2

目標 : **$enc(m_1)とenc(m_2)の最終ブロックが同じ \ and\ m_1 \neq m_2$**

暗号部分は、なぜか分けているけどAES-CBCと同じ動作するので、細かいことは気にしない。

ということで、$m' = m_2$と$m'' = m_1+m_2$を用意するが、$iv\neq enc(m_1\oplus iv)$ではないため動かない。

先ほどより$c_1$が既知なことを利用してとして$m' = m_2\oplus c_1  \oplus iv$と$m'' = m_1+m_2$とすれば求まる。

```python
enc123 = (m1+m2).hex()
enc23 = (bxor(bxor(c1,iv),m2)).hex()
print(enc123)
print(enc23)
# shaktictf{double_cheese_double_mac_yummyyyy_4120686170707920636263206d6f6465}
```



## [crypto]  r3deem_r4Nd0m　[6 solve]

### chall

```python
from hashlib import sha256
from Crypto.Util.number import *
from secret import p,q,r,flag


# p,q,r = getPrime(256),getPrime(256),getPrime(256)
n =  p*q*r
e = 65537
phi = (p-1)*(q-1)*(r-1)
d = inverse(e,phi)
ct = pow(bytes_to_long(flag),e,n)

h =int(sha256(flag).hexdigest(),16)

dp = d%(p-1)
dq = d%(q-1)
dr = d%(r-1)

sp = pow(h,dp,p)
sq = pow(h,dq,q)
sr = pow(h,dr,r)

s = (((sp*q*r*(inverse(q*r,p)))%n) + (sq*p*r*(inverse(p*r,q)) %(n)) + ((sr*p*q*(inverse((p*q),r)))%n))%n 
```

```python
from r3d33m_r4Nd0m import sp,sq,sr,h,e,n,ct
from Crypto.Util.number import * 
from secret import flag,p,q,r

def crt(sp1,sq1,sr1,p,q,r):
    s1 = (sp1*q*r*(inverse((q*r),p)))%n
    s2 = (sq1*p*r*(inverse((p*r),q)))%n
    s3 = (sr1*p*q*(inverse((p*q),r)))%n 
    s = (s1+s2+s3)%n 
    return s1,s2,s3,s 
    
def server():
    print(f"Welcome to this small crt game\nI am a poor kid, I am here to do a small job which can help me to coverup my small expenses.\nSo, My job is to do some simple calulations for inputs provided.\n\nAs part of game rules, intially I will give you some parameters, using that parameters and this server try to get me the flag , then you can get the treasure\nParameters provided\nn = {n}\ne = {e}\nh = {h}\nct = {ct}\nPlease try to give valid input, if I am unable do good calulations, my boss will fire me :( \nYou have two options:\n\n1. Input '1' to get sp,sq,sr values and it's computation values from our server\n2. Input '2' to input your own sp,sq,sr and get corresponding computatuion values" )
    
    x = input()
    if x == '1':
        print(f"sp = {sp}\nsq = {sq}\nsr = {sr}")
        s1,s2,s3,s = crt(sp,sq,sr,p,q,r)
        print(f"s1 = {s1}\ns2 = {s2}\ns3 = {s3}\ns = {s}")
    if x == '2':
        print("Get customized s1,s2,s3 and s values.")
        print("Input sp,sq,sr values")
        sp_u = int(input("\nInput your sp value: "))
        sq_u = int(input("\nInput your sq value: "))
        sr_u = int(input("\nInput your sr value: "))
        s1_u,s2_u,s3_u,s_u = crt(sp_u,sq_u,sr_u,p,q,r)
        print(f"s1 = {s1_u}\ns2 = {s2_u}\ns3 = {s3_u}\ns = {s_u}")

if __name__ == '__main__':
    server()

    
```



### solve

RSAで暗号され、その素数でCRTを行うものが渡される。

とりあえず、素数$p,q,r$がわからないと始まらないので、CRTをうまく用いて割り出していく。

$s_1 = q\*r \* (q\*r \mod p) -k\*n=q\*r \* ((q\*r \mod p) -k\*p) $より$q\*r=GCD(s_1,n)$から$p$がわかる。これを同様にすれば他の値もすぐに求まる。

```python
from Crypto.Util.number import *
n = 671193456450696209294538401092132200835318782822322315634822979842491480350953125013703551172675245349609262913412939263137349891298234146269765976476713743829345089919755818249576374672896649899144345865055014963972247204207494479
e = 65537
ct = 562424961019202732191255280916393150126209218444188556517270687960305550759526781461098153889147500792001380371454899207533680446302990359819605368684890785759571941069404593981778618037030554910233447127875225743078821221483182353
s1 = 299975575615366431743442900345501820171302184916013790549258989583702124067113757045635815940516169014707886648203282728770493017593176259766163134766679080376970009232489603551294208308458498129957898345431067389579567886412734956
s2 = 634658493680316046522130611451479798630743814754138967420984564261348394927938620704099453345768485030779025330014580509993617335353452850125123544790400738121047937373231722413387921371961136162073670869158916961134003314014005256
s3 = 470074781431408813402769135661849283210474606932730644990171152572265111532273848127919937536197133365570762332224403240917868298063908774205995365446224500933717346898118648118764091769080701066160085582010046429901107442705628137
s = 62321937825698873079265845274566500341883040958238771690768746732332669825419975850248104477131296711839148483616387953407278868414069591557750092049876831773045113664328337584293472103707035559902963066490000852670184234717379391


p = n//GCD(s1,n)
q = n//GCD(s2,n)
r = n//GCD(s3,n)
assert n == p*q*r
d = pow(e,-1,(p-1)*(q-1)*(r-1))
print(long_to_bytes(int(pow(ct,d,n))))
```

