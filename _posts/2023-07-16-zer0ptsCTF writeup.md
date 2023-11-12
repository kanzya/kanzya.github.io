---
title: zer0pts 2023 writeup
author: kanon
date: 2023-07-16 00:00:00 +0900
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


# zer0ptsCTF

久しぶりに長時間参加した気がする...

## 前置き　

Project Sekaiで参加してました。結果は18位なのでomgって感じですね。。。

実際参加してる人が少なかった＋メインの人がほぼいなかったのも大きいんですかね...

代わりにMr godがいましてrevを爆速で全部終わらしてました(強すぎる)

残りは、upsolveしたら追加します。。。

## SquareRNG [crypto 54 solve ] \(30 minuts\)

### chall

```python
#!/usr/bin/env python3
import os
from Crypto.Util.number import getPrime, getRandomRange

def isSquare(a, p):
    return pow(a, (p-1)//2, p) != p-1

class SquareRNG(object):
    def __init__(self, p, sa, sb):
        assert sa != 0 and sb != 0
        (self.p, self.sa, self.sb) = (p, sa, sb)
        self.x = 0

    def int(self, nbits):
        v, s = 0, 1
        for _ in range(nbits):
            self.x = (self.x + 1) % p
            s += pow(self.sa, self.x, self.p) * pow(self.sb, self.x, self.p)
            s %= self.p
            v = (v << 1) | int(isSquare(s, self.p))
        return v

    def bool(self):
        self.x = (self.x + 1) % self.p
        t = (pow(self.sa, self.x, self.p) + pow(self.sb, self.x, self.p))
        t %= self.p
        return isSquare(t, self.p)

p = getPrime(256)

sb1 = int(input("Bob's seed 1: ")) % p
sb2 = int(input("Bob's seed 2: ")) % p
for _ in range(77):
    sa = getRandomRange(1, p)
    r1 = SquareRNG(p, sa, sb1)
    print("Random 1:", hex(r1.int(32)))
    r2 = SquareRNG(p, sa, sb2)
    print("Random 2:", hex(r2.int(32)))

    guess = int(input("Guess next bool [0 or 1]: "))
    if guess == int(r1.bool()):
        print("OK!")
    else:
        print("NG...")
        break
else:
    print("Congratz!")
    print(os.getenv("FLAG", "nek0pts{*** REDACTED ***}"))
```

### solve

LCG$s_x \equiv \sum_{i=1}^{x}(sa^x\*sb^x) + 1\mod p$の出力に関して$(s_x/p)$の[ルジャンドル記号](https://ja.wikipedia.org/wiki/ルジャンドル記号)の値が$sb$が2回入力できることから2つ得られるので、そこから$(sa^{33}+sb^{33} /p)$のルジャンドル記号の出力を当てろっていう感じみたいです。

そもそも、ルジャンドル記号はその数$a$がある素数$p$において$a \equiv x^2 \mod p$となるような$x$の存在の判定するものです。

ルジャンドル記号には平方剰余の相互法則という$(a/p)*(b/p) = (ab/p)$があるのでこれを使えたらなーという気持ちで**男は黙って因数分解**します。

ここで、$sa^{33}+sb^{33}$を因数分解しちゃって、$sa^{33}+sb^{33} = (sa + sb) \* (sa^2 - sa\*sb + sb^2) \* (sa^{10} - sa^9\*sb + sa^8\*sb^2 - sa^7\*sb^3 + sa^6\*sb^4 - sa^5\*sb^5 + sa^4\*sb^6 - sa^3\*sb^7 + sa^2\*sb^8 - sa\*sb^9 + sb^10) \* (sa^{20} + sa^{19}\*sb - sa^{17}\*sb^3 - sa^{16}\*sb^4 + sa^{14}\*sb^6 + sa^{13}\*sb^7 - sa^{11}\*sb^9 - sa^{10}\*sb^10 - sa^9\*sb^{11} + sa^7\*sb^{13} + sa^6\*sb^{14} - sa^4\*sb^{16} - sa^3\*sb^{17} + sa\*sb^{19} + sb^{20})$ってなります。めでたく因数分解できた(てか対称式なので当たり前)ので、さっき貰った出力に置き換えていきます。

ここで、最初の項以外をかけわせてしまえば、$sa^{32} - sa^{31}\*sb + sa^{30}\*sb^2 - sa^{29}\*sb^3 + sa^{28}\*sb^4 - sa^{27}\*sb^5 + sa^{26}\*sb^6 - sa^{25}\*sb^7 + sa^{24}\*sb^8 - sa^{23}\*sb^9 + sa^{22}\*sb^{10} - sa^{21}\*sb^{11} + sa^{20}\*sb^{12} - sa^{19}\*sb^{13} + sa^{18}\*sb^{14} - sa^{17}\*sb^{15} + sa^{16}\*sb^{16} - sa^{15}\*sb^{17} + sa^{14}\*sb^{18} - sa^{13}\*sb^{19} + sa^{12}\*sb^{20} - sa^{11}\*sb^{21} + sa^{10}\*sb^{22} - sa^9\*sb^{23} + sa^8\*sb^{24} - sa^7\*sb^{25} + sa^6\*sb^{26} - sa^5\*sb^{27} + sa^4\*sb^{28} - sa^3\*sb^{29} + sa^2\*sb^{30} - sa\*sb^{31} + sb^{32} = \sum_{i=1}^{x}(sa^x + (-sb)^x) + 1$

$sb$に$-sb$を代入したときに得られた項の最終項と一致します。さらに残りの$sa+sb$は仮に$sb=1$とすると？$sa+1$となりこれは、$s_1 \equiv sa + 1\mod p$と同値なので、$sb1=1,sb2=-1$を代入します。そこから結果の1bitを掛け算すると答えが出ます。

```python
from Crypto.Util.number import getPrime, getRandomRange
from pwn import *

io = remote("crypto.2023.zer0pts.com","10666")

io.sendlineafter(b": ",b"1")
io.sendlineafter(b": ",b"-1")
for i in range(77):
    ct1 = eval(io.recvline().decode().split(" ")[-1])
    ct2 = eval(io.recvline().decode().split(" ")[-1])
    ct1 = bin(ct1)[2:].zfill(32)
    ct2 = bin(ct2)[2:].zfill(32)

    ans = (1-(int(ct2[-1])^int(ct1[0])))%2
    io.sendlineafter(b": ",str(int(ans)).encode())
    print(io.recvline())
io.interactive()

# zer0pts{L(a)L(b)=L(ab)}
```



## easy_factoring (coworker solved) [crypto 95 solve ] \(?? minuts\)

### chall

```python
import os
import signal
from Crypto.Util.number import *

flag = os.environb.get(b"FLAG", b"dummmmy{test_test_test}")

def main():
    p = getPrime(128)
    q = getPrime(128)
    n = p * q

    N = pow(p, 2) + pow(q, 2)

    print("Let's factoring !")
    print("N:", N)

    p = int(input("p: "))
    q = int(input("q: "))

    if isPrime(p) and isPrime(q) and n == p * q:
        print("yey!")
        print("Here you are")
        print(flag)
    else:
        print("omg")

def timeout(signum, frame):
    print("Timed out...")
    signal.alarm(0)
    exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(30)
    main()
    signal.alarm(0)

```

### solve???

さっきのLCG解いて休憩したらsahuangパイセンとquasarさんが爆速で解いてました(多分unintend)ので、また今度のupsolveってことで....

$N = p^2+q^2$の$p,q$を求めよということですが、なんということでしょう**ディオファントス問題**(だよね??)

**まぁOTOKO HA DAMATTE INSUUBUNKAI** $N=(p+qi)*(p-qi)$って感じですね。んで、複素数体自体はUFDだけどその$(p+qi)$自体がさらに因数を持つ可能性があるので因数の積で出るのかなぁ？(知らない)

## elliptic_ring_rsa [crypto 27 solve ] \(2 hour\)

### chall

```python
import string
import random
import os

flag = os.environb.get(b"FLAG", b"dummmmy{test_test_test}")

class EllipticRingElement:
	point = None
	def __init__(self, point):
		self.point = point
	
	def __add__(self, other):
		if self.point == dict():
			return other
		if other.point == dict():
			return self
		res = self.point.copy()
		for k in other.point.keys():
			if k in res:
				res[k] += other.point[k]
				if res[k] == 0:
					res.pop(k)
			else:
				res[k] = other.point[k]
				if res[k] == 0:
					res.pop(k)
		return EllipticRingElement(res)
	
	def __mul__(self, other):
		if self.point == dict() or other.point == dict():
			return self.point()
		res = dict()
		for k1 in other.point.keys():
			for k2 in self.point.keys():
				E = k1 + k2
				k = other.point[k1] * self.point[k2]
				if E in res:
					res[E] += k
					if res[E] == 0:
						res.pop(E)
				else:
					res[E] = k
					if res[E] == 0:
						res.pop(E)
		return EllipticRingElement(res)
	
	def __repr__(self):
		st = ""
		for k in self.point.keys():
			st += f"{self.point[k]}*({k[0]}, {k[1]}) + "
		return st[:-3]
	
class EllipticRing:
	E = None
	Base = None
	def __init__(self, E):
		self.E = E
		self.Base = E.base()

	def __call__(self, pt):
		for P in pt:
			pt[P] = self.Base(pt[P])
		return EllipticRingElement(pt)
	
	def zero(self):
		return EllipticRingElement(dict())
	
	def one(self):
		return EllipticRingElement({E(0): self.Base(1)})
	
	def pow(self, x, n):
		res = self.one()
		while n:
			if (n & 1):
				res = res * x
			x = x * x
			n >>= 1
		return res
	
	def encode(self, m, length):
		left = random.randint(0, length - len(m))
		pad1 = "".join(random.choices(string.ascii_letters, k=left)).encode("utf-8")
		pad2 = "".join(random.choices(string.ascii_letters, k=length-len(m)-left)).encode("utf-8")
		m = pad1 + m + pad2

		Ps = []
		while len(Ps) < length:
			PP = self.E.random_element()
			if PP not in Ps:
				Ps.append(PP)
		Ps = sorted(Ps)

		M = dict()
		for coef, pt in zip(m, Ps):
			M[pt] = self.Base(coef)
		return EllipticRingElement(M)
	
def random_prime_bits(nbits):
	return random_prime(2^nbits-1, false, 2^(nbits-1))

nbits = 8
p = random_prime_bits(nbits)
Fp = GF(p)

a = Fp.random_element()
b = Fp.random_element()
E = EllipticCurve(Fp, [a, b])

ER = EllipticRing(E)

P = ER.encode(flag, 30)

e = 13
C = ER.pow(P, e)

print(f"p: {p}")
print(f"C: {C}")
print(f"a: {a}")
print(f"b: {b}")
print(f"e: {e}")
```

### solve

とりあえず楕円は楕円だけど演算が..?て感じなので見ていきます。

なんか$A' =a_0\*P_0 + a_2\*P_2 + ...+a_{r-1}\*P_{r-1}$って感じの元に見えますねこれ。

掛け算は、多項式の掛け算と同じで$A'\*B' = \sum_{i=0}^{r-1}\sum_{j=0}^{r-1}((a_i+b_j)\*P_{i+j})$って感じですね。

足し算も、多項式の掛け算と同じで$A'+B' = \sum_{i=0}^{r-1}(a_i+b_j)\*P_{i})$って感じ。

乗算における逆元は....$A = (1+P_1)$等が存在しないはず！(理由は後程)

てな感じで多項式環に準同型写像出来そうですねこれ！！

ならこの元全体の集合を$G$、写像先の集合を$H$とすると、$\phi : G\to H:  P_i \mapsto x^i$っていう多項式への写像を構成することにします。

ここで、$A$の世界で行われていたことを考えてみると、**$P$という元を構築し、$P^e$しているだけです。**

ってことで**$\phi$→rsaのような逆演算→$\hat \phi$** で元に戻ります。

#### STEP1 写像の作成

とりあえず基準となる$g \in A$を探します(位数は最大のもの)、それを使って写像します。

```python
def plus2dict(_C):
    cc = dict()
    _C = _C.split(" + ")
    for c in _C:
        if c.split("*")[1] == "(0, 1)":
            cc[E(0)] = c.split("*")[0]
        else:
            cc[E(eval(c.split("*")[1]))] = c.split("*")[0]
    _C = cc
    return _C

PR.<x> = PolynomialRing(GF(p))
gen = x^192-1
QR.<x> = QuotientRing(PR, gen)

while True:
    g = E.random_element()
    if g.order() == r:
        break
    
def ec2vec(g,_C):
    vec = 0
    for i in range(0,r):
        try:
            vec += (int(_C[g*i])*x^i)
        except KeyError as e:
            continue
    return vec

C = plus2dict(C)
C = ec2vec(g,C)
```

これでおしまい。

#### PART2 rsa likeな復号

$A' \in G$から$A'\'\in H$に写像できたので、$H$について考えます。

$Z_p\[x\]/(X^{192}-1)$という群構造を持ちます。ここで、$x^{192}-1$は因数分解できてしまい、規約多項式にはなりませんので拡大体にはならないのですべての元が乗法での逆元を持ちません。($(X+1)\| X^{192}-1$より逆元を持たない、かつさっきの写像を考えると...)

よって、$H$は多項式環になるので多項式環のrsaの復号を考えます。

略しますが、位数は$p^k-1$の約数なことが知られていています。ここで、**Men must keep their mouths shut and factorize**すると$e \| p^k-1$といういやーな感じですが、位数的には$A'\'^{p^k-1//e} \equiv 1 \mod p$で問題なかったのでよしとします。

よって、通常のRSAっぽく$d = e^{-1} \mod (p^k-1)//e$として、$B'\'\equiv A'\'^d \mod p $で最終的に復号できます。

```python
d = int(pow(13,-1,(p^192-1)//13))
print((C^d))
m = str(C^d)
```

#### PART3 逆写像

最後に逆写像して終わりです。

最初に求めた$g$を基準にして逆写像していきます。

```python
ms = []
ps = []
for i in m.split(" + ")[:-1]:
    g_tmp = g*int(i.split("^")[1])
    ms.append([g_tmp,chr(int(i.split("*")[0]))])
    ps.append(g_tmp)
```

これで、最後にソートして順に係数を文字に起こしてやるとflagが求まります。

写像考えるのまじで楽しかったです。あと、これはそれなりに実行速度早いはず..??(知らんけど)

ってことで、これの想定解が気になるところ...??

```python
ps_ori = str([i.xy() for i in ps])
ps_sort = sorted(ps)
print(ps_ori)
ps_ori = [E(i) for i in eval(ps_ori)]
for i in range(len(ps_sort)):
    num = ps_ori.index(ps_sort[i])
    print(ms[num][1],end="")
# zer0pts{Gr0up_r1ng_meow!!}
```



```cakectfpython
C = "182*(91, 45) + 147*(3, 164) + 85*(62, 60) + 53*(77, 59) + 99*(77, 152) + 18*(137, 59) + 106*(169, 101) + 147*(127, 127) + 154*(152, 163) + 121*(43, 73) + 155*(110, 160) + 202*(116, 45) + 195*(1, 84) + 106*(71, 162) + 33*(209, 122) + 112*(134, 164) + 186*(1, 127) + 72*(183, 116) + 141*(141, 39) + 72*(83, 127) + 157*(197, 175) + 6*(178, 24) + 106*(71, 49) + 114*(57, 201) + 95*(181, 58) + 1*(174, 44) + 193*(202, 27) + 182*(121, 95) + 52*(167, 179) + 109*(184, 177) + 110*(21, 162) + 101*(126, 170) + 208*(47, 102) + 168*(129, 105) + 209*(179, 123) + 210*(160, 70) + 10*(13, 103) + 159*(76, 55) + 165*(31, 26) + 31*(44, 119) + 47*(6, 70) + 150*(74, 47) + 117*(30, 65) + 3*(108, 69) + 61*(43, 138) + 151*(72, 209) + 122*(110, 51) + 127*(44, 92) + 64*(191, 113) + 61*(45, 70) + 155*(91, 166) + 175*(95, 194) + 97*(21, 49) + 210*(66, 191) + 129*(129, 106) + 210*(80, 7) + 157*(174, 167) + 45*(141, 172) + 189*(155, 78) + 160*(194, 1) + 209*(82, 28) + 142*(164, 136) + 135*(199, 155) + 166*(118, 95) + 100*(123, 14) + 203*(121, 116) + 22*(36, 20) + 33*(65, 58) + 196*(189, 60) + 75*(137, 152) + 22*(125, 4) + 45*(119, 162) + 59*(47, 109) + 102*(177, 157) + 196*(109, 20) + 112*(192, 94) + 97*(209, 89) + 67*(95, 17) + 129*(75, 55) + 34*(134, 47) + 156*(60, 156) + 135*(127, 84) + 11*(148, 147) + 194*(202, 184) + 27*(45, 141) + 131*(4, 166) + 166*(148, 64) + 183*(164, 75) + 177*(130, 145) + 128*(107, 8) + 204*(156, 40) + 131*(17, 25) + 99*(177, 54) + 122*(82, 183) + 52*(178, 187) + 130*(168, 19) + 14*(150, 150) + 173*(167, 32) + 82*(184, 34) + 172*(72, 2) + 144*(169, 110) + 7*(118, 116) + 96*(181, 153) + 34*(133, 5) + 97*(207, 17) + 24*(78, 161) + 54*(57, 10) + 90*(143, 188) + 172*(130, 66) + 179*(146, 65) + 38*(55, 202) + 170*(63, 31) + 99*(35, 65) + 162*(150, 61) + 56*(74, 164) + 146*(144, 85) + 196*(133, 206) + 164*(152, 48) + 139*(176, 153) + 92*(125, 207) + 124*(31, 185) + 136*(0, 1) + 118*(107, 203) + 28*(24, 56) + 66*(171, 151) + 127*(76, 156) + 63*(208, 59) + 187*(146, 146) + 138*(85, 0) + 195*(19, 190) + 115*(60, 55) + 87*(171, 60) + 194*(17, 186) + 79*(75, 156) + 181*(27, 37) + 38*(192, 117) + 168*(13, 108) + 41*(143, 23) + 167*(199, 56) + 177*(86, 71) + 160*(35, 146) + 165*(189, 151) + 130*(32, 30) + 39*(108, 142) + 197*(36, 191) + 176*(120, 17) + 180*(194, 210) + 204*(19, 21) + 160*(6, 141) + 195*(109, 191) + 194*(155, 133) + 62*(65, 153) + 6*(138, 107) + 12*(201, 62) + 43*(180, 43) + 178*(208, 152) + 86*(180, 168) + 135*(55, 9) + 5*(138, 104) + 118*(207, 194) + 58*(160, 141) + 173*(66, 20) + 16*(179, 88) + 181*(61, 131) + 3*(80, 204) + 137*(119, 49) + 106*(126, 41) + 127*(176, 58) + 64*(144, 126) + 96*(30, 146) + 165*(168, 192) + 104*(27, 174) + 64*(63, 180) + 35*(123, 197) + 111*(86, 140) + 141*(197, 36) + 83*(116, 166) + 159*(4, 45) + 165*(62, 151) + 94*(183, 95) + 133*(3, 47) + 58*(83, 84) + 149*(201, 149) + 96*(20, 112) + 141*(191, 98) + 113*(24, 155) + 139*(61, 80) + 73*(120, 194) + 116*(78, 50) + 68*(156, 171) + 31*(32, 181)"
p = 211
a = 201
b = 102
e = 13
r = 192 # E.order()
E = EllipticCurve(GF(p),[a,b])

def plus2dict(_C):
    cc = dict()
    _C = _C.split(" + ")
    for c in _C:
        if c.split("*")[1] == "(0, 1)":
            cc[E(0)] = c.split("*")[0]
        else:
            cc[E(eval(c.split("*")[1]))] = c.split("*")[0]
    _C = cc
    return _C

PR.<x> = PolynomialRing(GF(p))
gen = x^192-1
QR.<x> = QuotientRing(PR, gen)

while True:
    g = E.random_element()
    if g.order() == r:
        break
print("[+] REFERNCE POINT",g)
    
def ec2vec(g,_C):
    vec = 0
    for i in range(0,r):
        try:
            vec += (int(_C[g*i])*x^i)
        except KeyError as e:
            continue
    return vec

C = plus2dict(C)
C = ec2vec(g,C)
d = int(pow(13,-1,(p^192-1)//13))
print("[+] AFTER DECRYPT",C^d)
m = str(C^d)

ms = []
ps = []
for i in m.split(" + ")[:-1]:
    g_tmp = g*int(i.split("^")[1])
    ms.append([g_tmp,chr(int(i.split("*")[0]))])
    ps.append(g_tmp)
    
print("[+] AFTER INVERSE MAPPING",ps)

ps_ori = str([i.xy() for i in ps])
ps_sort = sorted(ps)
ps_ori = [E(i) for i in eval(ps_ori)]
print("[+] FLAG : ",end="")
for i in range(len(ps_sort)):
    num = ps_ori.index(ps_sort[i])
    print(ms[num][1],end="")

# zer0pts{Gr0up_r1ng_meow!!}
```
