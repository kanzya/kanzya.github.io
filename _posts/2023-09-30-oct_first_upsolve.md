---
title: 十月初週のupsolve
author: kanon
date: 2023-09-30 00:00:00 +0900
categories: [writeup]
tags: [writeup]
math: true
mermaid: true
# image:
#   path: /commons/devices-mockup.png
#   width: 800
#   height: 500
#   alt: Responsive rendering of Chirpy theme on multiple devices.
---

# 十月初週のupsolve

時間的に出れなかったやつ+解けなかったやつのupsolve

時間が許す限り書いてみた。他にもやったけど忘れた...

## ASISCTF refactor

### chall

```python
#!/usr/bin/env python3

from Crypto.Util.number import *
from flag import flag

def pgen(nbit):
	x, y = 0, 1
	while True:
		u, v = getRandomRange(1, 110), getRandomRange(1, 313)
		print(u, v )
		x, y = u * x + 31337 * v * y, v * x - u * y
		if x.bit_length() <= nbit // 2 and x.bit_length() <= nbit // 2:
			p = x**2 + 31337 * y**2 | 1
			if isPrime(p) and p.bit_length() >= nbit:
				return p,x**2 + 31337 * y**2 
		else:
			print()
			x, y = 0, 1

def encrypt(msg, pkey):
	e, n = pkey
	m = bytes_to_long(msg)
	c = pow(m, e, n)
	return c

p, q = [pgen(1024) for _ in '__']
pkey = (31337, p * q)

c = encrypt(flag, pkey)

print(f'n = {p * q}')
print(f'c = {c}')
```

### solve

はじめは一次変換で何とかできんのかねと思ってましたが。。。特に行列の線形で何とかできるわけでもなく

適当に生成した$p = 383335841611474253288258749967087188658203719865678826202588775827454938897094153644206800790962935429622538072389187334174056071856288025761508719826829572233136259075355366784281390335902964426872367689398610556483495586882838606704940310135146159104045784806491756138016281172853224810405203956107889868800$が以下に素因数分解できるので、

$2^32 \* 3^41 \* 5^2 \* 7^13 \* 23^3 \* 43^2 \* 47^3 \* 59^2 \* 83^2 \* 139 \* 149 \* 229 \* 239 \* 257 \* 271 \* 307 \* 673 \* 677 \* 683 \* 691 \* 769 \* 919 \* 1163 \* 1289 \* 4691 \* 4969 \* 6229 \* 9157 \* 10799 \* 16883 \* 16979 \* 29837 \* 31337 \* 34807 \* 44953 \* 65633 \* 77999 \* 235099 \* 267781 \* 271027 \* 378283 \* 545023 \* 594469 \* 644647 \* 1498009 \* 1535837 \* 6577127 \* 11794219 \* 12075199 \* 14300119 \* 17062301 \* 22574411 \* 41120153 \* 50521253 \* 91379653 \* 111311803 \* 524726357 \* 581782787 \* 1026631601$

さすがに、なんかあるなぁと思って、$x_{i+1}, y_{i+1} = u_{i} \* x_{i} + 31337 \* v_{i} \* y_{i}, v_{i} \* x_{i} - u_{i} \* y_{i}$と漸化式を置いて、$p=x_1^2 + 31337 \* y_1^2+1$を求めると、ええ感じに因数分解$p=(x_0^2 + 31337\*y_0^2) * (u_0^2 + 31337\*v_0^2)+1$になったことより$(u_0^2 + 31337\*v_0^2)$の全てを求めることができるので、pollardのp-1で求まりそうな予感

```python
n = 15354257069173285781905276045639014609593379926482050489113547339117588412057832262093892509606681500550900795674355198875730897090963848584014735402479257641196755288572505568604616504895577156519599359709585689487167929035277328860394887100644352498762646576634768748203691626550604902474991908656069443025123380468043304218262437495617397923826383876725820263637369772201236276175774820781740263113457945850397866995318921153304724846886489062447149970082086628646772837892015556355384776002878980523779509899708723447721484662031731419684247739500573264103203416815345858413217500504527510275599764791910780108801
c = 11319719392368830772976523857976369154729855326260479489071566552409492905894844561614086707874832191432242950123964961582894044688274348653418226595519872495639236324552876924940961325755770656445013054487327399663358245181836741250528901918846037855858412978924591011941242779828600098063462814300900861180897010043498668688944295535981632815932395145673684660722012731208682402231321184600968865557231738026003707732466182970622224802483189066444000715061144732475930157185474148162121034705457395021374353689284243509307079898846581316271587575615363632603786729853488699442091342820074301120194843407072588515822
from Crypto.Util.number import *

cand = [u**2 + 31337 * v**2 for u in range(110) for v in range(313)]
tmp = Zmod(n)(c)
for k in cand[1:]:
    tmp ^= k
    if GCD(tmp-1,n)!=1:
        p = GCD(tmp-1,n)
        break
else:
    print("NOT FOUND")
q = n//p
e = 31337

for i in GF(p)(c).nth_root(e,all=True):
    if b"ASIS" in long_to_bytes(int(i)):
        print(long_to_bytes(int(i)))

# ASIS{P0lL4rd5_p-1_Al9oR!7Hm_gg!!}
```

もとまった。楽

## maplectf RNG

### chall

```python
from Crypto.Util.number import getPrime
from secret import flag
import random

class RNG:
    def __init__(self, s, a):
        self.s = s
        self.a = a

    def next(self):
        self.s = (self.s * self.a) % (2 ** 128)
        return self.s >> 96


if __name__ == "__main__":
    rng1 = RNG(getPrime(128), getPrime(64))
    rng2 = RNG(getPrime(128), getPrime(64))

    assert flag.startswith("maple{") and flag.endswith("}")
    flag = flag[len("maple{"):-1]

    enc_flag = []
    for i in range(0, len(flag), 4):
        enc_flag.append(int.from_bytes(flag[i:i+4].encode(), 'big') ^ rng1.next() ^ rng2.next())
    
    outputs = []
    for _ in range(42):
        if random.choice([True, False]):
            rng1.next()
        
        if random.choice([True, False]):
            rng2.next()

        if random.choice([True, False]):
            outputs.append(rng1.next())
        else:
            outputs.append(rng2.next())


    print("RNG 1:", rng1.a)
    print("RNG 2:", rng2.a)
    print("Encrypted flag:", enc_flag)
    print("Outputs:", outputs)
```

### solve

この問題CTF中はめんどすぎて解いてませんでした(わかったならやるべきだよなぁ、反省してます)

まずはkurenaifさんのturncated LCGを詳しく見てください。

さて、今回の設定としては2つのLCGの出力がランダムに与えられます。

そもそもとしてturncated LCGはLLLの部分で適当に工夫すれば非連続でも解ける時があるので、これをうまく使っていきます。

```python
from sage.all import QQ
from sage.all import ZZ
from sage.all import matrix
from sage.all import vector

# modified for https://github.com/jvdsn/crypto-attacks/blob/master/attacks/lcg/truncated_state_recovery.py
def tlcg(y, k, s, m, a, c):
    diff_bit_length = k - s

    # Preparing for the lattice reduction.
    delta = c % m
    yi = [_[1] for _ in y]
    y = vector(ZZ, [_[0] for _ in y])
    for i in range(len(y)):
        # Shift output value to the MSBs and remove the increment.
        y[i] = (y[i] << diff_bit_length) - delta
        delta = (a * delta + c) % m

    # This lattice only works for increment = 0.
    B = matrix(ZZ, len(y), len(y))
    B[0, 0] = m
    for i in range(1, len(y)):
        B[i, 0] = a ** yi[i]
        B[i, i] = -1

    B = B.LLL()

    # Finding the target value to solve the equation for the states.
    b = B * y
    for i in range(len(b)):
        b[i] = round(QQ(b[i]) / m) * m - b[i]

    # Recovering the states
    delta = c % m
    x = list(B.solve_right(b))
    for i, state in enumerate(x):
        # Adding the MSBs and the increment back again.
        x[i] = int(y[i] + state + delta)
        delta = (a * delta + c) % m

    return x
```



```python
from Crypto.Util.number import *
from itertools import combinations
from tqdm import tqdm
from lll import tlcg
a1 = 17858755236422136913
a2 = 10444850750214055793
ct =  [3999539808, 1592738381, 1057217965, 215730455, 2499659667]
Outputs = [3110779950, 3143489116, 2523808356, 59145943, 424415688, 1607693531, 2579126212, 1755297842, 3906113295, 1470215707, 3409703846, 3241626049, 3619900521, 3320623221, 2749059114, 775644902, 2452534658, 1107040405, 1783853908, 280554339, 3216758786, 2250874382, 2218107153, 4254508193, 2241158217, 2648593639, 2984582005, 3238054409, 3573713662, 2295623647, 1012063687, 1503914767, 2705122053, 2969541370, 2233703326, 1334624347, 1016155206, 2288145534, 2614694809, 1778390279, 999900406, 2501497460]
Outputs2 = [3110779950, 3143489116, 2523808356, 59145943, 424415688, 1607693531, 2579126212, 1755297842, 3906113295, 1470215707, 3409703846, 3241626049, 3619900521, 3320623221, 2749059114, 775644902, 2452534658, 1107040405, 1783853908, 280554339, 3216758786, 2250874382, 2218107153, 4254508193, 2241158217, 2648593639, 2984582005, 3238054409, 3573713662, 2295623647, 1012063687, 1503914767, 2705122053, 2969541370, 2233703326, 1334624347, 1016155206, 2288145534, 2614694809, 1778390279, 999900406, 2501497460]

class RNG:
    def __init__(self, s, a):
        self.s = s
        self.a = a
        self.a_inv = pow(a,-1,2 ** 128)

    def back(self):
        self.s = (self.s * self.a_inv) % (2 ** 128)
        return self.s >> 96
    def next(self):
        self.s = (self.s * self.a) % (2 ** 128)
        return self.s >> 96

def oracle(i0,i1,i2,i3,i4):
    for k0,k1,k2,k3,k4 in combinations(range(15), 5):
        y = [(Outputs[i0],k0-k0),(Outputs[i1],k1-k0),(Outputs[i2],k2-k0),(Outputs[i3],k3-k0),(Outputs[i4],k4-k0)]
        state1 = attack(y, 128, 128-96, 2**128, a1, 0)
        state2 = attack(y, 128, 128-96, 2**128, a2, 0)
        # print(state1)
        rng1 = RNG(state1[-1],a1)
        rng2 = RNG(state2[-1],a2)
        
        for i in range(10):
            if rng1.next() in Outputs:
                print("FOUND STATE1",state1[0],(i0,i1,i2,i3,i4),(k0,k1,k2,k3,k4))
                return state1[0],(i0,i1,i2,i3,i4),(k0,k1,k2,k3,k4)
            if rng2.next() in Outputs:
                print("FOUND STATE2",state2[0],(i0,i1,i2,i3,i4),(k0,k1,k2,k3,k4))
                return state2[0],[i0,i1,i2,i3,i4],[k0,k1,k2,k3,k4]
    return False 

for i0,i1,i2,i3,i4 in tqdm(combinations(range(8), 5)):
    i0,i1,i2,i3,i4 = (1, 3, 4, 6, 7)
    tmp = oracle(i0,i1,i2,i3,i4)
    if tmp!=False:
        state1, iis, _ = tmp
        break

rng1 = RNG(state1,a1)
rng1.back()
for i in range(1000):
    tmp = rng1.next()
    if tmp in Outputs2:
        Outputs2[Outputs2.index(tmp)] = 0

state2 = []
for i in range(15):
    if Outputs2[i] !=0:
        state2.append(i)
state2 = oracle(*state2[:5])[0]
print(state1)
print(state2)

for i in range(4):
    for k in range(4):
        rng1 = RNG(state1,a1)
        rng2 = RNG(state2,a2)
        
        for _ in range(i):
            rng1.back()
        for _ in range(k):
            rng2.back()
        
        m = []
        for l in range(5):
            m.append(long_to_bytes(ct[4-l]^rng2.back()^rng1.back()))
        print(m[::-1])
        print()

b"maple{lcgs_and_lattices}"
```

