---
title: HackTM writeup
author: kanon
date: 2023-02-19 00:00:00 +0900
categories: [ctf, writeup]
tags: [ctf, writeup]
math: true
mermaid: true
# image:
#   path: /commons/devices-mockup.png
#   width: 800
#   height: 500
#   alt: Responsive rendering of Chirpy theme on multiple devices.
---

# 初めに

SECCON終わりの初フル参加CTFでした。SECCONでぼこされたので、初心忘るべからずでいきました。

色々見てる感じ Double Lariat のメンバー誘えば良かったと後悔...orz
多分いい所まで行けたんじゃないかなぁ...


# \[crypto\] d-phi-enc 

## chall

```python
from Crypto.Util.number import bytes_to_long, getStrongPrime

from secret import flag

assert len(flag) == 255
e = 3
p = getStrongPrime(1024, e=e)
q = getStrongPrime(1024, e=e)
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
enc_d = pow(d, e, n)
enc_phi = pow(phi, e, n)
enc_flag = pow(bytes_to_long(flag), e, n)
print(f"{n = }")
print(f"{enc_d = }")
print(f"{enc_phi = }")
print(f"{enc_flag = }")

```

## solve

$enc_{phi}  \equiv phi^e \mod n,enc_d  \equiv d^e \mod n$ から $phi$ を復元すればおっけーです。

なので $e^e\*enc_d \equiv (ed)^e \mod n \equiv (k\*phi+1)^e \mod n$ で$k$は2であることが手元で実験してわかってるので、 多項式gcdで$phi$だして後は良しなに...

```python
from Crypto.Util.number import *
from sage.all import *
n = 24476383567792760737445809443492789639532562013922247811020136923589010741644222420227206374197451638950771413340924096340837752043249937740661704552394497914758536695641625358888570907798672682231978378863166006326676708689766394246962358644899609302315269836924417613853084331305979037961661767481870702409724154783024602585993523452019004639755830872907936352210725695418551084182173371461071253191795891364697373409661909944972555863676405650352874457152520233049140800885827642997470620526948414532553390007363221770832301261733085022095468538192372251696747049088035108525038449982810535032819511871880097702167
enc_d = 23851971033205169724442925873736356542293022048328010529601922038597156073052741135967263406916098353904000351147783737673489182435902916159670398843992581022424040234578709904403027939686144718982884200573860698818686908312301218022582288691503272265090891919878763225922888973146019154932207221041956907361037238034826284737842344007626825211682868274941550017877866773242511532247005459314727939294024278155232050689062951137001487973659259356715242237299506824804517181218221923331473121877871094364766799442907255801213557820110837044140390668415470724167526835848871056818034641517677763554906855446709546993374
enc_phi = 3988439673093122433640268099760031932750589560901017694612294237734994528445711289776522094320029720250901589476622749396945875113134575148954745649956408698129211447217738399970996146231987508863215840103938468351716403487636203224224211948248426979344488189039912815110421219060901595845157989550626732212856972549465190609710288441075239289727079931558808667820980978069512061297536414547224423337930529183537834934423347408747058506318052591007082711258005394876388007279867425728777595263973387697391413008399180495885227570437439156801767814674612719688588210328293559385199717899996385433488332567823928840559
enc_flag = 24033688910716813631334059349597835978066437874275978149197947048266360284414281504254842680128144566593025304122689062491362078754654845221441355173479792783568043865858117683452266200159044180325485093879621270026569149364489793568633147270150444227384468763682612472279672856584861388549164193349969030657929104643396225271183660397476206979899360949458826408961911095994102002214251057409490674577323972717947269749817048145947578717519514253771112820567828846282185208033831611286468127988373756949337813132960947907670681901742312384117809682232325292812758263309998505244566881893895088185810009313758025764867
e = 3

poly_gcd = lambda g1, g2: g1.monic() if not g2 else poly_gcd(g2, g1%g2)

PR.<phi> = PolynomialRing(Zmod(n))

poly = [(2*phi +1)^e - enc_d * e^3,
        phi^3 -enc_phi,]

phi = poly_gcd(poly[0],poly[1]).small_roots()[0]

PR.<p,q> = QQ[]

polys = [
    p*q -n,
    (p-1)*(q-1) - int(phi),
]
I = Ideal(polys)
ans = I.variety(ring=ZZ)[0]
p, q = ans[p], ans[q]

d = pow(e,-1,int(phi))

print(long_to_bytes(int(pow(enc_flag,d,n))))

# HackTM{Have you warmed up? If not, I suggest you consider the case where e=65537, although I don't know if it's solvable. Why did I say that? Because I have to make this flag much longer to avoid solving it just by calculating the cubic root of enc_flag.}
```



# \[crypto\] kaitenzushi

## chall

```python
from math import gcd
from Crypto.Util.number import bytes_to_long, isPrime

from secret import p, q, x1, y1, x2, y2, e, flag

# properties of secret variables
assert isPrime(p) and p.bit_length() == 768
assert isPrime(q) and q.bit_length() == 768
assert isPrime(e) and e.bit_length() == 256
assert gcd((p - 1) * (q - 1), e) == 1
assert x1.bit_length() <= 768 and x2.bit_length() <= 768
assert y1.bit_length() <= 640 and y2.bit_length() <= 640
assert x1 ** 2 + e * y1 ** 2 == p * q
assert x2 ** 2 + e * y2 ** 2 == p * q

# encrypt flag by RSA, with xor
n = p * q
c = pow(bytes_to_long(flag) ^^ x1 ^^ y1 ^^ x2 ^^ y2, e, n)
print(f"{n = }")
print(f"{c = }") ,

# hints 🍣
F = RealField(1337)
x = vector(F, [x1, x2])
y = vector(F, [y1, y2])
# rotate
theta = F.random_element(min=-pi, max=pi)
R = matrix(F, [[cos(theta), -sin(theta)], [sin(theta), cos(theta)]])
x = R * x
y = R * y
print(f"{x = }")
print(f"{y = }")

```

## solve

見た感じ $x1,y1,x2,y2$ の復元をやらないと始まんないみたいですね。

てなわけで、方針として以下の感じになります。

1. $x1,y1,x2,y2$ の復元
2. $p,q$ の素因数分解



### part1

写像後のprintされているものを $X_i,Y_i$ にして式に書くと下の感じになる。

$$\begin{bmatrix} X_1 & Y_1 \\ X_2 & Y_2\end{bmatrix}  =\begin{bmatrix} cos(\theta) & sin(\theta) \\ sin(\theta) & cos(\theta)\end{bmatrix} \begin{bmatrix} x_1 & y_1 \\ x_2 & y_2\end{bmatrix}$$

さらに、$x_1^2 + e\* y_1^2 = p\*q,x_2^2 + e\* y_2^2 = p\*q$であることも考えると

全て変数化して、終結式へ投げるといい感じに帰ってくる

```python
def resultant(f1, f2, var):
    return Matrix(f1.sylvester_matrix(f2, var)).determinant()

PR.<c,s,e,x0,x1,y0,y1,n> = QQ[]
polys = [
    c^2 + s^2 - 1,
    (x0*c + x1*s)^2 + e*(c* y0 + s*y1)^2 - n,
    (x1*c + x0*(-s))^2 + e*(c* y1 + (-s)*y0)^2 - n,
]
print(resultant(polys[1], polys[2], s))
# s side
# 4*s^4*x0^2*x1^2*y0^4 + 4*s^4*x1^4*y0^4 - 8*s^4*x0^3*x1*y0^3*y1 - 8*s^4*x0*x1^3*y0^3*y1 + 4*s^4*x0^4*y0^2*y1^2 + 8*s^4*x0^2*x1^2*y0^2*y1^2 + 4*s^4*x1^4*y0^2*y1^2 - 8*s^4*x0^3*x1*y0*y1^3 - 8*s^4*x0*x1^3*y0*y1^3 + 4*s^4*x0^4*y1^4 + 4*s^4*x0^2*x1^2*y1^4 - 8*s^4*x1^2*y0^4*n + 16*s^4*x0*x1*y0^3*y1*n - 8*s^4*x0^2*y0^2*y1^2*n - 8*s^4*x1^2*y0^2*y1^2*n + 16*s^4*x0*x1*y0*y1^3*n - 8*s^4*x0^2*y1^4*n - 4*s^2*x0^2*x1^2*y0^4 - 4*s^2*x1^4*y0^4 + 8*s^2*x0^3*x1*y0^3*y1 + 8*s^2*x0*x1^3*y0^3*y1 - 4*s^2*x0^4*y0^2*y1^2 - 8*s^2*x0^2*x1^2*y0^2*y1^2 - 4*s^2*x1^4*y0^2*y1^2 + 8*s^2*x0^3*x1*y0*y1^3 + 8*s^2*x0*x1^3*y0*y1^3 - 4*s^2*x0^4*y1^4 - 4*s^2*x0^2*x1^2*y1^4 + 4*s^4*y0^4*n^2 + 8*s^4*y0^2*y1^2*n^2 + 4*s^4*y1^4*n^2 + 8*s^2*x1^2*y0^4*n - 16*s^2*x0*x1*y0^3*y1*n + 8*s^2*x0^2*y0^2*y1^2*n + 8*s^2*x1^2*y0^2*y1^2*n - 16*s^2*x0*x1*y0*y1^3*n + 8*s^2*x0^2*y1^4*n + x1^4*y0^4 - 2*x0^2*x1^2*y0^2*y1^2 + x0^4*y1^4 - 4*s^2*y0^4*n^2 - 8*s^2*y0^2*y1^2*n^2 - 4*s^2*y1^4*n^2 - 2*x1^2*y0^4*n + 2*x0^2*y0^2*y1^2*n + 2*x1^2*y0^2*y1^2*n - 2*x0^2*y1^4*n + y0^4*n^2 - 2*y0^2*y1^2*n^2 + y1^4*n^2
```

後は代入すると、

```python
n  = ----[snipped]----
ct = ----[snipped]----
x  = ----[snipped]----
y  = ----[snipped]----

F = RealField(1337)
PR.<s> = PolynomialRing(F)
x0,x1 = x
y0,y1 = y
poly_s = 4*s^4*x0^2*x1^2*y0^4 + 4*s^4*x1^4*y0^4 - 8*s^4*x0^3*x1*y0^3*y1 - 8*s^4*x0*x1^3*y0^3*y1 + 4*s^4*x0^4*y0^2*y1^2 + 8*s^4*x0^2*x1^2*y0^2*y1^2 + 4*s^4*x1^4*y0^2*y1^2 - 8*s^4*x0^3*x1*y0*y1^3 - 8*s^4*x0*x1^3*y0*y1^3 + 4*s^4*x0^4*y1^4 + 4*s^4*x0^2*x1^2*y1^4 - 8*s^4*x1^2*y0^4*n + 16*s^4*x0*x1*y0^3*y1*n - 8*s^4*x0^2*y0^2*y1^2*n - 8*s^4*x1^2*y0^2*y1^2*n + 16*s^4*x0*x1*y0*y1^3*n - 8*s^4*x0^2*y1^4*n - 4*s^2*x0^2*x1^2*y0^4 - 4*s^2*x1^4*y0^4 + 8*s^2*x0^3*x1*y0^3*y1 + 8*s^2*x0*x1^3*y0^3*y1 - 4*s^2*x0^4*y0^2*y1^2 - 8*s^2*x0^2*x1^2*y0^2*y1^2 - 4*s^2*x1^4*y0^2*y1^2 + 8*s^2*x0^3*x1*y0*y1^3 + 8*s^2*x0*x1^3*y0*y1^3 - 4*s^2*x0^4*y1^4 - 4*s^2*x0^2*x1^2*y1^4 + 4*s^4*y0^4*n^2 + 8*s^4*y0^2*y1^2*n^2 + 4*s^4*y1^4*n^2 + 8*s^2*x1^2*y0^4*n - 16*s^2*x0*x1*y0^3*y1*n + 8*s^2*x0^2*y0^2*y1^2*n + 8*s^2*x1^2*y0^2*y1^2*n - 16*s^2*x0*x1*y0*y1^3*n + 8*s^2*x0^2*y1^4*n + x1^4*y0^4 - 2*x0^2*x1^2*y0^2*y1^2 + x0^4*y1^4 - 4*s^2*y0^4*n^2 - 8*s^2*y0^2*y1^2*n^2 - 4*s^2*y1^4*n^2 - 2*x1^2*y0^4*n + 2*x0^2*y0^2*y1^2*n + 2*x1^2*y0^2*y1^2*n - 2*x0^2*y1^4*n + y0^4*n^2 - 2*y0^2*y1^2*n^2 + y1^4*n^2


# print(poly_s.roots())
_, _, c, s = [_[0] for _ in  poly_s.roots()]
```

これで $sin(\theta),cos(\theta)$の値がわかった。ただ、候補が2つある(正回転or逆回転)ので代入して、値が整数ということを考えてやれば一意に決まる。

```python
def solve_xs_ys(s,c):
    x  = ----[snipped]----
    y  = ----[snipped]----

    F = RealField(1337)
    x = vector(F, [_ for _ in x])
    y = vector(F, [_ for _ in y])
    # rotate
    R = matrix(F, [[c, -s], [s, c]])
    x = R^(-1) * x
    y = R^(-1) * y
    # print(f"{x = }")
    # print(f"{y = }")
    return x,y

# true
# print(solve_xs_ys(s,c))
# ret = (1.23343431936894440973263647479974540141395074556779828339916509613682879668610901423506961118285523166037774054833601787794419590891163752205158573276826154790166536984681500991748749778629881670438838666011425669518792357094873553000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005e230, -9.93315378106395196440156892634615357425859001976376351903878161126954317590016249318316631584063366449446002974804447367756266228508159317926113473123770241598131922105753478630709094061327843793983555725542453353312556415777678936999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999998e230), (2.95702891759040183827241488621026109955415212852401225663178715196876893509028690821994463400830412991408307468450766653970029004782754586267046590672581397139817053510458959806568392753705926800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e192, -1.93518098174342694414424160720807163740044134017573004218248685165604434384710484681124817651698709818703976889508767807895216618103609127904817977547152172876909535027087606807328610207963607999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999989e191)
ret = (123343431936894440973263647479974540141395074556779828339916509613682879668610901423506961118285523166037774054833601787794419590891163752205158573276826154790166536984681500991748749778629881670438838666011425669518792357094873553, -993315378106395196440156892634615357425859001976376351903878161126954317590016249318316631584063366449446002974804447367756266228508159317926113473123770241598131922105753478630709094061327843793983555725542453353312556415777678937), (2957028917590401838272414886210261099554152128524012256631787151968768935090286908219944634008304129914083074684507666539700290047827545862670465906725813971398170535104589598065683927537059268, -193518098174342694414424160720807163740044134017573004218248685165604434384710484681124817651698709818703976889508767807895216618103609127904817977547152172876909535027087606807328610207963608)
(x1, x2), (y1, y2)  = ret
```

これで、part1はおしまい。

### part2

難関??なのか風呂入ってたら思いつきました。

兎にも角にも $e$ は速攻でわかるので、出しておきます。

```python
x0,x1 = x
y0,y1 = y
poly_e = (x0*c + x1*s)^2 + e*(c* y0 + s*y1)^2 - n
print(poly_e.roots())
#[(1.1157800980263640943712375759161704818976014542355242141862733874983591656180100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e77, 1)]
e = 111578009802636409437123757591617048189760145423552421418627338749835916561801

```

本題です。

今回は条件として $x1,y1,x2,y2$ が楕円上の有理点であることから、$x_1^2 + e\* y_1^2 = p*q,x_2^2 + e\* y_2^2 = p\*q$ の等式が成り立つ。

一旦、$\mod p$ を取ると

$$ x_1^2 + e* y_1^2 \equiv 0 \mod p $$

$$ x_2^2 + e* y_2^2 \equiv 0 \mod p $$

ここで、上の式には $y_2^2$ を、下の式には $y_1^2$ を、かけてやると以下になる。

$$ (x_1y_2)^2 + e* (y_1y_2)^2 \equiv 0 \mod p $$

$$ (x_2y_1)^2 + e* (y_1y_2)^2 \equiv 0 \mod p $$

仮に、ある $x_{tmp}$ が座標に存在すると $±y_{tmp}$ も同様に存在します。このことも加味すると

$$ (x_1y_2)^2 \equiv (x_2y_1)^2$$

$$ ±x_1y_2 \equiv \mp x_2y_1 $$

これより $p,q$ どちらかの素数が出すことができるので復号しておわり。

```python
p = GCD(int(x1*y2 -x2*y1),n)
q = n//p
print(p)
assert p*q == n
n  = ----[snipped]----
ct = ----[snipped]----
x  = ----[snipped]----
y  = ----[snipped]----
e = 111578009802636409437123757591617048189760145423552421418627338749835916561801
p = 957509848415776008506125961998120495161250346184055094697245571121876444575553394581756735245207167681344755095903616730328731358607257251854603846193989936802222147961302618645021044609662945352893811478461448918625795339911124621
ret = (123343431936894440973263647479974540141395074556779828339916509613682879668610901423506961118285523166037774054833601787794419590891163752205158573276826154790166536984681500991748749778629881670438838666011425669518792357094873553, -993315378106395196440156892634615357425859001976376351903878161126954317590016249318316631584063366449446002974804447367756266228508159317926113473123770241598131922105753478630709094061327843793983555725542453353312556415777678937), (2957028917590401838272414886210261099554152128524012256631787151968768935090286908219944634008304129914083074684507666539700290047827545862670465906725813971398170535104589598065683927537059268, -193518098174342694414424160720807163740044134017573004218248685165604434384710484681124817651698709818703976889508767807895216618103609127904817977547152172876909535027087606807328610207963608)
(x1, x2), (y1, y2)  = ret

q = n//p
phi = (p-1)*(q-1)
d = pow(int(e),-1,phi)

m = pow(c,d,n)
print(m)
m = x1 ^ y1 ^ x2 ^ y2 ^ m
print(m.bit_length())
print(long_to_bytes(int(m)))

# HackTM{r07473_pr353rv35_50m37h1n6}
```

ただ、復号すると ***HackTM{r07473_pr353rv35_50m37h1n6s***になるので何かミスってる可能性あるかも...????

でも、ここまで来たら初心者OSINTして***s → }***だろってことで出したら通りました。GG




# \[crypto\] broken_oracle (can't solve)


## chall

```python
#!/usr/local/bin/python3
"""
implementation of https://www.cs.umd.edu/~gasarch/TOPICS/miscrypto/rabinwithrecip.pdf
"""
import os
import random
from dataclasses import dataclass
from math import gcd
from typing import List, Tuple

import gmpy2
from Crypto.Util.number import bytes_to_long, getPrime

from secret import flag


@dataclass
class Pubkey:
    n: int
    c: int


@dataclass
class Privkey:
    p: int
    q: int


@dataclass
class Enc:
    r: int
    s: int
    t: int

    def __repr__(self) -> str:
        return f"r = {self.r}\ns = {self.s}\nt = {self.t}"


def crt(r1: int, n1: int, r2: int, n2: int) -> int:
    g, x, y = gmpy2.gcdext(n1, n2)
    assert g == 1
    return int((n1 * x * r2 + n2 * y * r1) % (n1 * n2))


def gen_prime(pbits: int) -> int:
    p = getPrime(pbits)
    while True:
        if p % 4 == 3:
            return p
        p = getPrime(pbits)


def genkey(pbits: int) -> Tuple[Pubkey, Privkey]:
    p, q = gen_prime(pbits), gen_prime(pbits)
    n = p * q
    c = random.randint(0, n - 1)
    while True:
        if gmpy2.jacobi(c, p) == -1 and gmpy2.jacobi(c, q) == -1:
            break
        c = random.randint(0, n - 1)

    pubkey = Pubkey(n=n, c=c)
    privkey = Privkey(p=p, q=q)
    return pubkey, privkey


def encrypt(m: int, pub: Pubkey) -> Enc:
    assert 0 < m < pub.n
    assert gcd(m, pub.n) == 1
    r = int((m + pub.c * pow(m, -1, pub.n)) % pub.n)
    s = int(gmpy2.jacobi(m, pub.n))
    t = int(pub.c * pow(m, -1, pub.n) % pub.n < m)
    enc = Enc(r=r, s=s, t=t)
    assert s in [1, -1]
    assert t in [0, 1]
    return enc


def solve_quad(r: int, c: int, p: int) -> Tuple[int, int]:
    """
    Solve x^2 - r * x + c = 0 mod p
    See chapter 5.
    """

    def mod(poly: List[int]) -> None:
        """
        Calculate mod x^2 - r * x + c (inplace)
        """
        assert len(poly) == 3
        if poly[2] == 0:
            return
        poly[1] += poly[2] * r
        poly[1] %= p
        poly[0] -= poly[2] * c
        poly[0] %= p
        poly[2] = 0

    def prod(poly1: List[int], poly2: List[int]) -> List[int]:
        """
        Calculate poly1 * poly2 mod x^2 - r * x + c
        """
        assert len(poly1) == 3 and len(poly2) == 3
        assert poly1[2] == 0 and poly2[2] == 0
        res = [
            poly1[0] * poly2[0] % p,
            (poly1[1] * poly2[0] + poly1[0] * poly2[1]) % p,
            poly1[1] * poly2[1] % p,
        ]
        mod(res)
        assert res[2] == 0
        return res

    # calculate x^exp mod (x^2 - r * x + c) in GF(p)
    exp = (p - 1) // 2
    res_poly = [1, 0, 0]  # = 1
    cur_poly = [0, 1, 0]  # = x
    while True:
        if exp % 2 == 1:
            res_poly = prod(res_poly, cur_poly)
        exp //= 2
        if exp == 0:
            break
        cur_poly = prod(cur_poly, cur_poly)

    # I think the last equation in chapter 5 should be x^{(p-1)/2}-1 mod (x^2 - Ex + c)
    # (This change is not related to vulnerability as far as I know)
    a1 = -(res_poly[0] - 1) * pow(res_poly[1], -1, p) % p
    a2 = (r - a1) % p
    return a1, a2


def decrypt(enc: Enc, pub: Pubkey, priv: Privkey) -> int:
    assert 0 <= enc.r < pub.n
    assert enc.s in [1, -1]
    assert enc.t in [0, 1]
    mps = solve_quad(enc.r, pub.c, priv.p)
    mqs = solve_quad(enc.r, pub.c, priv.q)
    ms = []
    for mp in mps:
        for mq in mqs:
            m = crt(mp, priv.p, mq, priv.q)
            if gmpy2.jacobi(m, pub.n) == enc.s:
                ms.append(m)
    assert len(ms) == 2
    m1, m2 = ms
    if m1 < m2:
        m1, m2 = m2, m1
    if enc.t == 1:
        m = m1
    elif enc.t == 0:
        m = m2
    else:
        raise ValueError
    return m


if __name__ == "__main__":
    pbits = 1024
    pub, priv = genkey(pbits)
    while len(flag) < 255:
        flag += os.urandom(1)
    enc_flag = encrypt(bytes_to_long(flag), pub)
    print("encrypted flag:")
    print(enc_flag)
    while True:
        try:
            r, s, t = map(int, input("r, s, t = ").split(","))
            enc = Enc(r=r, s=s, t=t)
            enc_dec_enc = encrypt(decrypt(enc, pub, priv), pub)
            print("decrypt(encrypt(input)):")
            print(enc_dec_enc)
        except Exception:
            print("Something wrong...")

```

## solve

初めに $priv,pub$ すら分かってないので、一旦、$p,q$ を求めていく。

具体的には、このシステムは*dec → enc* を行ってくれるもの、たまに入力した $enc$ ではない値が出ることがあるので、それを使って $p,q$ を求めていく。

帰ってくる値としては(多分) $a, a+k_1p,a+k_2q,a+k_3p+k_3q$的な感じだと思う。なので、GCD を上手く使ってやる

```python

def find_n(io,p,n):
    
    cnt = 1
    factors =set()
    while True:    
        ret = []
        for _s in [-1,1]:
            for _t in [0,1]:
                tmp = send_ans(cnt,_s,_t)
                if False == tmp:
                    return False
                ret.append(tmp[0])
        
        if len(set(ret)) ==2:
            _ = abs(ret[0]-ret[1])
            _ = factor(_,limit=10^8)[-1][0]
            factors.add(_)
        
        if len(set(ret)) ==4:
            _ = GCD(abs(ret[0]-ret[2]) ,abs(ret[3]-ret[1]))
            _ = factor(_,limit=10^8)[-1][0]
            factors.add(_)
        
        fac_list = list(factors)
        fac_list.sort()
        
        for i in fac_list:
            for k in fac_list:
                if GCD(i,k) !=1:
                    factors.add(GCD(i,k))
        if len(factors) <3:
            cnt +=1
            continue
        
        if int(fac_list[0]).bit_length() < 1025 and int(fac_list[1]).bit_length() < 1025 and int(fac_list[0])!=1 and int(fac_list[1])!=1:
            print("ret=",int(fac_list[0]),int(fac_list[1]))
            return int(fac_list[0]),int(fac_list[1])
        cnt +=1
```

これで、 $priv$ の復元が終わったので、$pub$ どうすっかなー問題の発生

### 案1 **$x^2 + E\*x + c$の剰余環を考える**

solve_quad関数で $x^{(p-1)//2} \equiv ax +b-1 \mod x^2 + E\*x + c$ を考えている
よって、安直に2変数の剰余環でいいかなぁって考えていたら toy implementation でいつまでたっても終わらない...

### 案2 **案1を encの解を$A_1,A_2$ として　グレブナーごり押し**

$x^{(p-1)//2}$ を $x^2 -Ex+c$ が割り切れない時に値がバグるので、この時のsolve_quad関数の解を $A_1,A_2$ とする。
ここで、$r = A_1 + {C \over A_1}$ であることから $r = A_1 + A_1 \* {C \over A_1\*A_2}$となる??

$$ r1 + r2 = A_1 + A_1 * {C \over A_1*A_2} + A_2 + A_2 * {C \over A_2*A_1} $$

$$ r1 * r2 = (A_1 + A_1 * {C \over A_1*A_2}) * (A_2 + A_2 * {C \over A_2*A_1}) $$

以上の式が成り立ちそう...???
でもとけぬ...げせぬ...

多分あってた....でも、 間に合わないです......orz

```python
# PR.<c> = PolynomialRing(GF(q))
PR.<C,C_prime> = PolynomialRing(GF(q))

# C_prime = A1 * A2
# i = A1 + A2
polys = [
    C_prime^2 +  (i^2 - 2*C_prime)*C + C^2 - C_prime* dec[0] * dec[1],
    i * (C + C_prime) - C_prime * (dec[0] + dec[1]),
]
I = Ideal(polys)
ans = I.variety()
print(ans)
```


# 追記
競技終了10分後に求まりました。泣きそうです。。。

## 方針
**案2で合っていてそれで終わります。GG**



```python

from pwn import *
from server import decrypt, Privkey,Pubkey,Enc
from random import randint
from factordb.factordb import FactorDB
import gmpy2
from Crypto.Util.number import *

poly_gcd = lambda g1, g2: g1.monic() if not g2 else poly_gcd(g2, g1%g2)

def send_ans(r,s,t):
    io.sendlineafter(b"r, s, t = ",(str(r)+","+str(s)+","+str(t)).encode())
    if b"Something" in io.recvline():
        return False
    return [int(_) for _ in  io.recvline().decode().split("=")[1].split(",")]
p = 0
n = 0

def find_n(io,p,n):
    
    cnt = 1
    p,n =0,0
    factors =set()
    while True:    
        ret = []
        for _s in [-1,1]:
            for _t in [0,1]:
                tmp = send_ans(cnt,_s,_t)
                if False == tmp:
                    return False
                ret.append(tmp[0])
        
        if len(set(ret)) ==2:
            _ = abs(ret[0]-ret[1])
            _ = factor(_,limit=10^8)[-1][0]
            factors.add(_)
        
        if len(set(ret)) ==4:
            _ = GCD(abs(ret[0]-ret[2]) ,abs(ret[3]-ret[1]))
            _ = factor(_,limit=10^8)[-1][0]
            factors.add(_)
        
        fac_list = list(factors)
        fac_list.sort()
        
        for i in fac_list:
            for k in fac_list:
                if GCD(i,k) !=1:
                    factors.add(GCD(i,k))
        if len(factors) <3:
            cnt +=1
            continue
        
        if int(fac_list[0]).bit_length() < 1025 and int(fac_list[1]).bit_length() < 1025 and int(fac_list[0])!=1 and int(fac_list[1])!=1:
            # print("ret=",int(fac_list[0]),int(fac_list[1]))
            return int(fac_list[0]),int(fac_list[1])
            return False
        cnt +=1

def find_c(io,p,q):
    
    p = int(str(p))
    q = int(str(q))
    retc = []
    for t_prime in [q,p]:
        for i in range(3,100):
            ret = []
            for _t in [0,1]:
                # for _s in [-1,1]:
                ret.append(send_ans(i,1,_t)[0])
            if len(set(ret)) !=2:
                continue
            # print(ret,i)
            if GCD(ret[0] - ret[1],t_prime) !=1:
                continue
            PR.<C,C_prime> = PolynomialRing(GF(t_prime))
            polys = [
                C_prime^2 +  (i^2 - 2*C_prime)*C + C^2 - C_prime* ret[0] * ret[1],
                i * (C + C_prime) - C_prime * (ret[0] + ret[1]),
            ]
            I = Ideal(polys)
            ans = I.variety()[1]
            print(t_prime,ans)
            retc.append([t_prime,ans[C]])
            break

    return retc
    

while True:
        
    io = remote("34.141.16.87", 50001)
    # io = process(["python3","server.py"])
    io.recvline()
    # rst
    exec(io.recvline(None).decode())
    exec(io.recvline(None).decode())
    exec(io.recvline(None).decode())

    print(r,s,t)
    tmp = find_n(io,p,n)
    
    if False == tmp:
        io.close()
        continue
    q,p = tmp
    n = p*q
    if p>q:
        p,q = q,p
    print(p,q)
    print("findc")
    cs = find_c(io,p,q)
    C = int(CRT([int(cs[0][1]),int(cs[1][1])],[int(cs[0][0]),int(cs[1][0])]))
    print("C",C)
    p = int(p)
    q = int(q)
    r = int(r)
    s = int(s)
    t = int(t)
    for c in cs:
        m = decrypt(Enc(r,s,t),Pubkey(n = p*q,c = C),Privkey(p=p,q=q))
        print(decrypt(Enc(r,s,t),Pubkey(n = p*q,c = C),Privkey(p=p,q=q)))
        print(long_to_bytes(int(m)))
        exit()

# b'HackTM{h4v3_y0u_r34lly_f0und_4ll_7h3_bu65...?}\x8d\xc3\xd5~vH\x918\xd1\t\x92 \x13v\xd9\xee\x8aS>B\xd3\xdbl\xe5\x88\xcfE\xfc\xa1\x18o@=\x8b\xfdI\x987]\xdc1\xa2"|\xc6\x0fO\xc6\x9c\xa8\xf9\xd3\xa3\x01\xdb\x04\t(+\xe9\xd7(s\xbb\xaa\xb7\xe2\xba\xd9\xf4\xfd\xde\xef\x0f\x84\x85.\xc01\x97\x13rJ\xa0\xba\xa7\x93&\x10\xb8\xde\x08\x1a\x1f\xb3I\x8e\x82\r\xb2\xda]\x1b;p\x16\xc7>\x86\xb3\x81\xd2\xf8\x04\xff\x15S\xf2\xbe\xcd\x98\xaaW\xfd\xe8\x88\xd9h\x11\x99\x1bo\xcaB\x95\x95\xccA\xefmx\x9c\xcf\xe3f\xd2\xd9\xf9\xe71\xefZ-d\x8e\x84\xbf,\xd6\x06S\x0b\xafiyWX\x8f\x91,":\xc5\xae\xea\x8f\xd1\x0b\x93\x13\x02\xe7>\xb2\x16\xf0\x80\xe4\xb5j\n\xd3S_C\xd7C\x8c#\xde\xd1W\x8b\xfet\n\xaf\rf
```


