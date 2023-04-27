---
title: CPCTF 2023 writeup
author: kanon
date: 2023-02-19 00:00:00 +0900
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

# CPCTF

なんか空き時間見つけて参加してました。面白かったです

## simple

### chall

```python
from Crypto.Util.number import inverse, bytes_to_long, getPrime
from flag import flag


class complex_over_p:
    """
    a + bi
    """

    def __init__(self, a, b, p):
        self.a = a
        self.b = b

        self.p = p

    def __mul__(self, other):
        return complex_over_p(
            (self.a * other.a - self.b * other.b) % self.p,
            (self.a * other.b + self.b * other.a) % self.p,
            self.p,
        )

    def __pow__(self, n: int):
        ret = complex_over_p(1, 0, self.p)
        x = complex_over_p(self.a, self.b, self.p)
        while n > 0:
            if n & 1:
                ret = ret * x
            x = x * x
            n >>= 1
        return ret

    def __str__(self):
        return str(self.a) + " + " + str(self.b) + "i"


p = getPrime(512)
q = getPrime(512)
n = p * q
phi = (p - 1) * (q - 1)
e = 65537

m = bytes_to_long((flag).encode("utf-8"))
c_1 = complex_over_p(p, m, n) ** e
c_2 = complex_over_p(q, m, n) ** e

with open("cipher.txt", "w") as f:
    f.write(f"c_1 = {str(c_1)}\n")
    f.write(f"c_2 = {str(c_2)}\n")
    f.write(f"n = {n}\n")
    f.write(f"e = {e}\n")

```



### solve

面白いですね。複素数体上での離散対数問題的な？？

とりあえず、こういうのは$p,q$を求めないと始まらないのが鉄則なので求めていきます。

$c_1 = (p+mi)^e=\sum_{i=0}^e {}_eC_i p^i(mi)^{e-i}$より実数部は$p$でくくれる気がします。よって、$p=GCD(Re(c_1),n)$で求まりそうな気がします。

さて、ここから問題で$m$を求めなければいけないですが、どうしたものかと。。。

$c_1 \equiv (p+mi)^e \mod n$より$c_1 \equiv (mi)^e \mod p$となるのでこれの虚数部を考えるとただのフェルマーの小定理ですよね！なら、$d \equiv e^{-1} \mod p-1$とすれば解決しますね！！

ここで一つ、$phi$についてミスリードではないかという話を見かけた気がするので。。。

実際そこだけ見るとミスリードな気もしますが、そもそもとして$p$の値を出せた時点でその辺の知識を理解しているものと考えていいような気がしますで、ミスリードにならないと私は考えますし、これは解いたうえでの私の意見です。

```python
c_1 = [88947353384906315386142174915579230007708484691905461586249734733895208303904624706955572569717469153074453837889147058757297004159523404800499566731846573280606881057150101844929178328363240743156762837486978571114151912836342740869293096891054377782752248810122413624567401981982628574682163267589540717955 , 105796218607197626508309219898970081654433389611035862776816738031930217893350585142033078143656160997324512315260317101196998029046142078518167267210684968483205795618377068578645969888568133775820377659323101885187136507439656053103103802476138541844262969937543381511564444761769799873705129093296227488320]
c_2 = [6246646181898635030418930144979030696163268885489193597189892517442414814959679853409630585655482080447639092928109757977342458025765218315720433756032748568912426451942636486110411038484872363928990656032625950245328223463301109739166158341796991125915052131277132622262221136515681121985807852466393611412 , 53817519046828021036896927561082153848829725683909509411136093993919199941896521025977358288420902565544951255959786518459773639829589216874164688208953119794504853435052217109342811249935881805211646847973929482665869312260539685753735469177452027367949870932823024534083790996822338074496201028292592498398]
n = 115660927134746496667389439939121894365639159618801107805144217447831876345527158612296725729945512010246362315164908359385194177739042272399000609673334050698528059482827768728850630523188582862374516240503442919767592843273925939238586765096529791229982128395675821790738782110235716669724330392693672332699
e = 65537

from Crypto.Util.number import *

p = GCD(n,88947353384906315386142174915579230007708484691905461586249734733895208303904624706955572569717469153074453837889147058757297004159523404800499566731846573280606881057150101844929178328363240743156762837486978571114151912836342740869293096891054377782752248810122413624567401981982628574682163267589540717955)
q = GCD(6246646181898635030418930144979030696163268885489193597189892517442414814959679853409630585655482080447639092928109757977342458025765218315720433756032748568912426451942636486110411038484872363928990656032625950245328223463301109739166158341796991125915052131277132622262221136515681121985807852466393611412,n)


assert p*q == n

class complex_over_p:
    """
    a + bi
    """

    def __init__(self, a, b, p):
        self.a = a
        self.b = b

        self.p = p

    def __mul__(self, other):
        return complex_over_p(
            (self.a * other.a - self.b * other.b) % self.p,
            (self.a * other.b + self.b * other.a) % self.p,
            self.p,
        )

    def __pow__(self, n: int):
        ret = complex_over_p(1, 0, self.p)
        x = complex_over_p(self.a, self.b, self.p)
        while n > 0:
            if n & 1:
                ret = ret * x
            x = x * x
            n >>= 1
        return ret

    def __str__(self):
        return str(self.a) + " + " + str(self.b) + "i"
    
dp = pow(e,-1,p-1)
mp = pow(c_1[1],int(dp),p)
print(long_to_bytes(mp))
```



## misuse

### chall

```python
"""This code is designed to be run with SageMath.
See https://www.sagemath.org/
If you don't have SageMath installed, you can use the online version at https://cocalc.com/ or https://sagecell.sagemath.org/
But you may not use pyton lib online...
ref: https://doc.sagemath.org/html/en/index.html
"""

from Crypto.Util.number import bytes_to_long, long_to_bytes, isPrime
from flag import flag
from Crypto.Cipher import AES
from base64 import b64encode
from secret import key
from Crypto.Util.Padding import pad


p = 1457379754778834114393428514496372769300186542434939310975944765431765709327445548009771988242361974038539406450275157591
a = 1236064211753439722521344199773932075287648377233139862790772102290062141518569630890922001641345393262197009050412379555
b = 1128111897991419355721141214155995058314857116431662004640521251265155838304469066234949556324122951758680646976644303642


def lift_x(x, p):
    assert p % 4 == 3
    z = (x**3 + a * x + b) % p
    res = pow(z, (p + 1) // 4, p)
    return res % p, -res % p


if __name__ == "__main__":
    assert isPrime(p)
    F = GF(p)
    m = flag.encode("utf-8")

    cipher = AES.new(long_to_bytes(key), AES.MODE_CBC)
    iv = cipher.iv
    c = cipher.encrypt(pad(m, AES.block_size))
    x = bytes_to_long(long_to_bytes(key) + c)
    assert x < p
    d = 65537
    ecc = EllipticCurve(F, [a, b])
    y = lift_x(x, p)[0]
    P = ecc(x, y)
    Q = d * P

    with open("public.txt", "w") as f:
        f.write(f"iv={bytes_to_long(b64encode(iv))}\n")
        f.write(f"Q_x={Q[0]}\n")
        f.write(f"Q_y={Q[1]}\n")

```

### solve

楕円曲線問題ですね。。。

$Q=[65537]P$となる$P$を見つけてほしいと。。。

位数を$r$とする時において$P=[e]Q$となるような$e$が存在する時、$P=[e]([65537]P)=[65537e]P)$となるわけですね！！

よって$65537e \mod r \equiv1$が成り立ち$e$を求めてGGですね!!



```python
from Crypto.Util.number import bytes_to_long, long_to_bytes, isPrime
from Crypto.Cipher import AES
from base64 import b64encode,b64decode
from Crypto.Util.Padding import pad
from attacks.ecc.mov_attack import attack


iv=1605329254557036569964018111218106639001485748371419774269
Q_x=1392303607889887553584136595208390161792050603172364540235291678701315789244344186052295822556700256817290239704363991998
Q_y=1217907436356492041789129865417129927287034438783900990437895711720259012753482269603468893642710812002767867785347902249


p = 1457379754778834114393428514496372769300186542434939310975944765431765709327445548009771988242361974038539406450275157591
a = 1236064211753439722521344199773932075287648377233139862790772102290062141518569630890922001641345393262197009050412379555
b = 1128111897991419355721141214155995058314857116431662004640521251265155838304469066234949556324122951758680646976644303642

ecc = EllipticCurve(GF(p), [a, b])
d = 65537
# r = ecc.order()
r = 1457379754778834114393428514496372769300186542434939310975942617452418525644269374582205991018703761232026759172619867624

Q = ecc(Q_x, Q_y)
Px = int(pow(d,-1,r))*Q
assert Px*d == Q

Px = Px.xy()[0]
Px = long_to_bytes(int(Px))

key = Px[:AES.block_size]
ct = Px[AES.block_size:]
cipher = AES.new(key, AES.MODE_CBC,iv=b64decode(long_to_bytes(int(iv))))
c = cipher.decrypt(ct)
print(c)
# 'CPCTF{Manual_is_imp0rtant}
```

