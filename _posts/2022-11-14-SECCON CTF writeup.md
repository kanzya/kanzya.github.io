---
title: SECCON CTF 2022 writeup
author: kanon
date: 2022-11-14 14:00:00 +0900
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
SECCONでちょっと出来なかったことが多すぎたので分かる範囲で纏めました。

jyankenとwitches_symmetric_examはまた次回にでも...
それよりも問題なのが**this_is_not_lsb**がほんとにLLLで解けるのかということで、手元で組んだ感じ全部失敗したのでなえてます。はい。。。

年末までにbit長さでのEHNPとHNPのお気持ちを理解したい所存です。(がんばるます…!!)

## pqpq

### chall

```python
from Crypto.Util.number import *
from Crypto.Random import *
from flag import flag

p = getPrime(512)
q = getPrime(512)
r = getPrime(512)
n = p * q * r
e = 2 * 65537

assert n.bit_length() // 8 - len(flag) > 0
padding = get_random_bytes(n.bit_length() // 8 - len(flag))
m = bytes_to_long(padding + flag)

assert m < n

c1p = pow(p, e, n)
c1q = pow(q, e, n)
cm = pow(m, e, n)
c1 = (c1p - c1q) % n
c2 = pow(p - q, e, n)

print(f"e = {e}")
print(f"n = {n}")
# p^e - q^e mod n
print(f"c1 = {c1}")
# (p-q)^e mod n
print(f"c2 = {c2}")
# m^e mod n
print(f"cm = {cm}")
```

### solve

#### 1STEP : $p,q,r$の導出

 $c_1 \equiv p^e - q^e \mod n,c_2 \equiv (p-q)^e \mod n$であることより$c_1-c_2 \equiv (p^e - q^e) - (p^e+q^e + \sum^{e-1}_{i=1}\ _eC_ip^i(-q)^{e-i})\equiv q(-2q^
{e-1}+ \sum^{e-1}_{i=1}\ _eC_ip^i(-q)^{e-i-1}))$となる。

よって、$n=pqr$であることより$c_1-c_2$と$n$のGCDを取れば$q$が求まる。

$c_1 \equiv p^e \mod q$, $e=2*65537$であるので $d \equiv 65537^{-1} \mod q-1$とすれば$p^2 \equiv c_1^d \mod q $となる。

よって、$p^2$の平方根を求めることで$p$がもとまると同時に$n$より$r$も求まる。



#### 2STEP : 復号

$GCD(e,(p-1)(q-1)(r-1))) \neq1 $より単純な計算では$d$が求まらないので、素数ごとに復元してCRTで求めるようにする。

よって$GCD(\frac{e}{2},(p-1)(q-1)(r-1))) =1 $より単純な計算で$\frac{e}{2}$の逆元を求めることで以下の式が求まる。

$ d_p \equiv \frac{e}{2}^{-1} \mod p-1,d_q \equiv \frac{e}{2}^{-1} \mod q-1,d_r \equiv \frac{e}{2}^{-1} \mod r-1$

よって、$m_p^2 \equiv cm^{d_p} \mod p,m_q^2 \equiv cm^{d_q} \mod q,m_r^2 \equiv cm^{d_r} \mod r$ となりそれぞれの平方根を組み合わせてCRTで復元してflagが求まる。

```python
from Crypto.Util.number import *
from Crypto.Random import *
from itertools import product
 

e = 131074
n = 587926815910957928506680558951380405698765957736660571041732511939308424899531125274073420353104933723578377320050609109973567093301465914201779673281463229043539776071848986139657349676692718889679333084650490543298408820393827884588301690661795023628407437321580294262453190086595632660415087049509707898690300735866307908684649384093580089579066927072306239235691848372795522705863097316041992762430583002647242874432616919707048872023450089003861892443175057
c1 = 92883677608593259107779614675340187389627152895287502713709168556367680044547229499881430201334665342299031232736527233576918819872441595012586353493994687554993850861284698771856524058389658082754805340430113793873484033099148690745409478343585721548477862484321261504696340989152768048722100452380071775092776100545951118812510485258151625980480449364841902275382168289834835592610827304151460005023283820809211181376463308232832041617730995269229706500778999
c2 = 46236476834113109832988500718245623668321130659753618396968458085371710919173095425312826538494027621684566936459628333712619089451210986870323342712049966508077935506288610960911880157875515961210931283604254773154117519276154872411593688579702575956948337592659599321668773003355325067112181265438366718228446448254354388848428310614023369655106639341893255469632846938342940907002778575355566044700049191772800859575284398246115317686284789740336401764665472
cm = 357982930129036534232652210898740711702843117900101310390536835935714799577440705618646343456679847613022604725158389766496649223820165598357113877892553200702943562674928769780834623569501835458020870291541041964954580145140283927441757571859062193670500697241155641475887438532923910772758985332976303801843564388289302751743334888885607686066607804176327367188812325636165858751339661015759861175537925741744142766298156196248822715533235458083173713289585866

# 1019 601 739
# 36230691
# e = 131074
# n = 452577641
# c1 = 64229228
# c2 = 200519200
# cm = 18095470
m = bytes_to_long(b"1234567890")
# p*q
q = GCD(c1-c2,n)
assert n%q == 0
pr = n// q
assert isPrime(q)

p2 = pow(c1,pow(e//2,-1,q-1),q)
# print(pow(c1,pow(e//2,-1,q-1),q))
# print(pow(823,e,q))
# print(823%q,pow(823,2,q))
# print(p2,q)

# print(mod(p2, q).sqrt(all = True))
# p = 7572427786695057270624844967644562609112132599800420296747189080920032359205995588384031542287784540006438555802994008688795974493684400576592403320929717

for p in mod(p2, q).sqrt(all = True):
    for i in range(2):
        p = int(p)
        p += i*q
        # print(p,isPrime(p))
        if n%p==0:
            # print(p)
            break
p = 7572427786695057270624844967644562609112132599800420296747189080920032359205995588384031542287784540006438555802994008688795974493684400576592403320929717
assert isPrime(p)
assert isPrime(q)
assert n%p==0
assert n%q==0 
r = n//(p*q)
# print(r)
assert isPrime(r)
assert n%r==0


def search(c,p):
    assert pow(mod(pow(c,pow(e//2,-1,p-1),p), p).sqrt(all = True)[0],e,p)==c
    return mod(pow(c,pow(e//2,-1,p-1),p), p).sqrt(all = True)



for cp,cq,cr in list(product(search(cm,p),search(cm,q),search(cm,r))):
    print(int(cp))
    # input()
    tmp = CRT([int(cp),int(cq),int(cr)],[p,q,r])
    if b"SECCON" in long_to_bytes(tmp):
        print(long_to_bytes(tmp))
        
# SECCON{being_able_to_s0lve_this_1s_great!}

```
{: file="solve.sage" }

## BBB

### chall

```python
from Crypto.Util.number import bytes_to_long, getPrime
from random import randint
from math import gcd
from secret import FLAG
from os import urandom

assert len(FLAG) < 100


def generate_key(rng, seed):
    e = rng(seed)
    while True:
        for _ in range(randint(10,100)):
            e = rng(e)
        p = getPrime(1024)
        q = getPrime(1024)
        phi = (p-1)*(q-1)
        if gcd(e, phi) == 1:
            break

    n = p*q
    return (n, e)


def generate_params():
    p = getPrime(1024)
    a = randint(0, p-1)

    return (p,a)


def main():
    p,a = generate_params()
    print("[+] The parameters of RNG:")
    print(f"{a=}")
    print(f"{p=}")
    b = int(input("[+] Inject [b]ackdoor!!: "))
    rng = lambda x: (x**2 + a*x + b) % p

    keys = []
    seeds = []
    for i in range(5):
        seed = int(input("[+] Please input seed: "))
        seed %= p
        if seed in seeds:
            print("[!] Same seeds are not allowed!!")
            exit()
        seeds.append(seed)
        n, e = generate_key(rng, seed)
        if e <= 10:
            print("[!] `e` is so small!!")
            exit()

        keys.append((n,e))

    flag = bytes_to_long(FLAG + urandom(16))
    for n,e in keys:
        c = pow(flag, e, n)
        print("[+] Public Key:")
        print(f"{n=}")
        print(f"{e=}")
        print("[+] Cipher Text:", c)


if __name__ == "__main__":
    main()
```

### upsolve

#### 競技時

競技時考えていたこととしては、この問題の特徴として

1. $n_i$ 同士に対しての共通な素数はない
2. $b$で二次関数を操作できる
   1. その二次関数から$e$が生成
3.  FLAGに対して128bitのpadding
4. $e$はLCG(2次関数)を適当に繰り返す(10-100回)
5. $e$が11以上

が見えたので、1からHastad's broadcast attack ができるのかなぁと思いつつ、初めに11個のインスタンスからそれぞれ$e=11$と固定したものを取ってきてHastad's broadcast attack やると当たり前ですが答えは出ません(3. のpaddingによって)。

なら、$e=12$にして2乗根を2回、3乗根を3回とれば出るかなと思いつつ実行すると、そもそも$GCD(e,phi)\neq 1$となりそもそもできなかった。

どうしたもんかなと思っていると、2次関数の性質として最大2個の解をもつことがあり、さらに言えば$b$で解を11にしているのでもう1つの解も11となることが言えます。これで2つのseedの値が得ることができたので、残りは以下の式 $\lim_{n \rightarrow\inf} e_{n+1} = e_n^2 + a*e_n +b$ なのでなんかこれ見たことあるなぁと思いまして。。。

![BBB](https://github.com/kanzya/photo/raw/main/SECCON/BBB.png)

少し違いますがイメージとして適当な形で表すとこんな感じ...

なら、$\lim_{n \rightarrow\inf} e_{n+1} = e_n$であることを追加して考えると$e_n = e_{n-1} \neq e_{n-2},\lim_{n \rightarrow\inf} e_{n} = e_{n-2}$でも問題ないよなと考えたので逆順となる$n \rightarrow n-1\rightarrow n-2$で$e$の値を求めれるじゃん…!!となったので、実装フェーズに移ります。

**ここで問題が発生**

sageって.roots()がありますよね...方程式の根を求めるやつ...あれの存在を完全に忘れていたので2次方程式の解の公式を実装したのですが、これやっちゃいました...

もうスクリプトはないのであれなんですが実装ミスって終わりました...



#### upsolve時

てことで、sageの.roots()を使って実装しました...orz

```python
from pwn import *
from gmpy2 import iroot
from Crypto.Util.number import *
from sage.all import *

def const_e(x, a, p):
    
    return (-x**2 - x*(a-1))%p

while True:
    ret = set()
    def serch_roots(p,a,e,b):
        PR = PolynomialRing(GF(p),"x")
        x = PR.gen()

        for i in (x*x +a*x +b -e).roots():
            if len(ret)>4:
                return  ret
            if i[0] in ret:
                continue
            ret.add(i[0])
            
            print("[+] find ",len(ret))
            serch_roots(p,a,int(i[0]),b)
        
        return None

    ns = []
    es = []
    cts = []
    e_ = 11

    io = remote( "BBB.seccon.games" ,8080)
    # io = process(["python3","chall.py"])

    io.recvline()

    exec(io.recvline().decode())
    exec(io.recvline().decode())

    io.recvuntil(b"!!: ")
    print("[+]p",bin(p)[-9:])
    b = const_e(e_,a,p)
    print("fin") 
    io.sendline(str(b).encode())


    li = serch_roots(p,a,e_,b)

    if li == None:
        io.close()
        continue
    for i in list(li):
            
        io.recvuntil(b" seed: ")
        io.sendline(str(i).encode())

    for i in range(5):
        io.recvline()
        exec(io.recvline().decode())
        exec(io.recvline().decode())

        ns.append(n)
        es.append(e)
        cts.append(eval(io.recvline().decode().replace("[+] Cipher Text: ","")))
    io.close()

    c = CRT(cts,ns)

    tmp = iroot(int(c),e_)
    print(tmp)
    if tmp[1] ==  True:
        print(long_to_bytes(iroot(int(c),e_)[0]))
        exit()

```



```bash
[+] Opening connection to BBB.seccon.games on port 8080: Done
[+]p 111011001
fin
[+] find  1
[+] find  2
[+] find  3
[+] find  4
[+] find  5
[*] Closed connection to BBB.seccon.games port 8080
(mpz(2883019091813529219737035153484934929534955887753874746941092955853444099264575760415715710120591467702376578902084283075705374264225673611778863370445183048344031472894050836959651658562832755850169071594495017590365639338557184317630010978441644681967727625313646557515818101), True)
b'SECCON{Can_you_find_d_in_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbdbbbbbbbbbbbbbbbbbbbbbbbbbbbbb?}\xf2\x07\xb3\xce\x19\xb8\x8bNH\xb0\xa6\xac\x10E$u'
```

## isufficient

### chall

```python
from random import randint
from Crypto.Util.number import getPrime, bytes_to_long
from secret import FLAG

# f(x,y,z) = a1*x + a2*x^2 + a3*x^3
#          + b1*y + b2*y^2 + b3*y^3
#          + c*z + s mod p
def calc_f(coeffs, x, y, z, p):
    ret = 0
    ret += x * coeffs[0] + pow(x, 2, p) * coeffs[1] + pow(x, 3, p)*coeffs[2]
    ret += y * coeffs[3] + pow(y, 2, p) * coeffs[4] + pow(y, 3, p)*coeffs[5]
    ret += z * coeffs[6]
    ret += coeffs[7]

    return ret % p


p = getPrime(512)


# [a1, a2, a3, b1, b2, b3, c, s]
coeffs = [randint(0, 2**128) for _ in range(8)]

key = 0
for coeff in coeffs:
    key <<= 128
    key ^= coeff

cipher_text = bytes_to_long(FLAG) ^ key
print(cipher_text)

shares = []
for _ in range(4):
    x = randint(0, p)
    y = randint(0, p)
    z = randint(0, 2**128)

    w = calc_f(coeffs, x, y, z, p)
    packed_share = ((x,y), w)
    shares.append(packed_share)

print(p)
print(shares)	

```


### 競技時

$ w = a_1\*x + a_2\*x^2 + a_3\*x^3+ b_1\*y + b_2\*y^2 + b_3\*y^3+ c\*z + s \mod p $ 、$x,y$は128bit、$p$は512bit、それ以外は128bitで式は4本与えられています。

既知の値は、それぞれの式の$x,y,w$だけで、目標は係数$a,b,z,c,s$の復元となります。

はじめに、まぁNHPなのでLLLかなと...思って格子を組みます。具体的に組んだ格子は以下のものです。(くそでかいですが)空白部分は0です

$$
\begin{bmatrix}
  p     &      &        &   \\
        & p    &&  \\
        &      & p      &  \\
        &       &       & p &&&&\\
  x_0   & x_1   & x_2   & x_3   & 2^{128}\\
  x_0^2 & x_1^2 & x_2^2 & x_3^2 && 2^{128} \\
  x_0^3 & x_1^3 & x_2^3 & x_3^3 &&& 2^{128} \\
  y_0   & y_1   & y_2   & y_3   &&&& 2^{128}\\
  y_1^2 & y_1^2 & y_2^2 & y_3^2 &&&&& 2^{128}  \\
  y_1^3 & y_1^3 & y_2^3 & y_3^3 &&&&&& 2^{128}\\
  -w_0  & -w_1  & -w_2  & -w_3  &&&&&&& 2^{512} \\
\end{bmatrix}
$$

ここで $  0\simeq c\*z + s = a_1\*x + a_2\*x^2 + a_3\*x^3+ b_1\*y + b_2\*y^2 + b_3\*y^3 -w +kp$と$a,b$の係数が128bitレベルなので対角成分に$1\*2^{128}$を、$w$は一度しか使いたくないので$1\*2^{512}$を与えてやってLLLを行う。

そうするとどこかの行ベクトルに今回用いた$a,b$の値に$2^{128}$されたものと、$2^{512}$が出てくるので探せば今回用いた値を求めることができた。よって今回求まった係数は$a,b,c,s$の内$a,b$となり残りの$c,s$については別途求めなければならない。

ここから行列の成分から$c\*z_i + s$の値は求まるがすべての変数が未知数でどうするのかわからなくて詰んだ...orz

```python
m = matrix(ZZ,N,N)

for i in range(4):
    m[4,i] = x[i]
    m[5,i] = pow(x[i],2,p)
    m[6,i] = pow(x[i],3,p)
    
    m[7,i] = y[i]
    m[8,i] = pow(y[i],2,p)
    m[9,i] = pow(y[i],3,p)
    m[10,i] = -w[i]

for i in range(N):
    m[i,i] = 2^128
    # m[i,i] = 1

for i in range(4):
    m[i,i] = p
m[10,10] = 2^512

m = m.LLL()

```



#### upsolve

これを求めるのは意外と単純でGCDでした。(競技中やった記憶あるんだけどなぁ...???)

$h_i \equiv c\*z_i + s \mod p $とすると$c,z_i,s$は128bitで$p$は512bitより実は、$h_i = c\*z_i + s$とも表せれることになる。最大公約数を用いて$c = GCD(h_i -h_{i+1},h_{i+1} -h_{i+2})$で求まります。。。

てことで、$h$の式において$c$の値が出ることがわかった。

ここで、128bitを128bitで割ると商の大きさはいくつでしょうか...?答えは0 or 1 なので、これを用いると$s$も求まります。$s = h_i\%c + \delta_ic$　ここで、$\delta$は0か1の数です。

これですべての係数が出そろったのでkeyを復元してflagが求まります。



```python
from Crypto.Util.number import *


ct = 115139400156559163067983730101733651044517302092738415230761576068368627143021367186957088381449359016008152481518188727055259259438853550911696408473202582626669824350180493062986420292176306828782792330214492239993109523633165689080824380627230327245751549253757852668981573771168683865251547238022125676591
p = 8200291410122039687250292442109878676753589397818032770561720051299309477271228768886216860911120846659270343793701939593802424969673253182414886645533851
xyw = [((6086926015098867242735222866983726204461220951103360009696454681019399690511733951569533187634005519163004817081362909518890288475814570715924211956186561, 180544606207615749673679003486920396349643373592065733048594170223181990080540522443341611038923128944258091068067227964575144365802736335177084131200721), 358596622670209028757821020375422468786000283337112662091012759053764980353656144756495576189654506534688021724133853284750462313294554223173599545023200), ((1386358358863317578119640490115732907593775890728347365516358215967843845703994105707232051642221482563536659365469364255206757315665759154598917141827974, 4056544903690651970564657683645824587566358589111269611317182863269566520886711060942678307985575546879523617067909465838713131842847785502375410189119098), 7987498083862441578197078091675653094495875014017487290616050579537158854070043336559221536943501617079375762641137734054184462590583526782938983347248670), ((656537687734778409273502324331707970697362050871244803755641285452940994603617400730910858122669191686993796208644537023001462145198921682454359699163851, 7168506530157948082373212337047037955782714850395068869680326068416218527056283262697351993204957096383236610668826321537260018440150283660410281255549702), 1047085825033120721880384312942308021912742666478829834943737959325181775143075576517355925753610902886229818331095595005460339857743811544053574078662507), ((5258797924027715460925283932681628978641108698338452367217155856384763787158334845391544834908979711067046042420593321638221507208614929195171831766268954, 4425317882205634741873988391516678208287005927456949928854593454650522868601946818897817646576217811686765487183061848994765729348913592238613989095356071), 866086803634294445156445022661535120113351818468169243952864826652249446764789342099913962106165135623940932785868082548653702309009757035399759882130676)]
x = []
y = []
w = []
for i in range(4):
    x.append(xyw[i][0][0])
    y.append(xyw[i][0][1])
    w.append(xyw[i][1])
N = 11
m = matrix(ZZ,N,N)

for i in range(4):
    m[4,i] = x[i]
    m[5,i] = pow(x[i],2,p)
    m[6,i] = pow(x[i],3,p)
    
    m[7,i] = y[i]
    m[8,i] = pow(y[i],2,p)
    m[9,i] = pow(y[i],3,p)
    m[10,i] = -w[i]

for i in range(N):
    m[i,i] = 2^128
    # m[i,i] = 1

for i in range(4):
    m[i,i] = p
m[10,10] = 2^512

m = m.LLL()
#cz+ s
cz_s = []
coffs = []
for k in range(4):
	cz_s.append(abs(m[-1,k]))
for k in range(4,N-1):
	coffs.append(m[-1,k]//2^128)

c = GCD(cz_s[0]-cz_s[1],cz_s[1]-cz_s[2])
coffs.append(c)

s = cz_s[0]%c
coffs.append(s)
print(cz_s)
print(coffs)
key = 0
for coff in coffs:
    key <<= 128
    key ^^= coff
    


cipher_text = int(ct) ^^ key
print(long_to_bytes(cipher_text))

b'SECCON{Unfortunately_I_could_not_come_up_with_a_more_difficult_problem_than_last_year_sorry...-6fc18307d3ed2e7673a249abc2e0e22c}'
```



## this_is_not_lsb

### chall

```python
from Crypto.Util.number import *
from flag import flag

p = getStrongPrime(512)
q = getStrongPrime(512)
e = 65537
n = p * q
phi = (p - 1) * (q - 1)

d = pow(e, -1, phi)

print(f"n = {n}")
print(f"e = {e}")
print(f"flag_length = {flag.bit_length()}")

# Oops! encrypt without padding!
c = pow(flag, e, n)
print(f"c = {c}")

# padding format: 0b0011111111........
def check_padding(c):
    padding_pos = n.bit_length() - 2
    m = pow(c, d, n)
    m = c
    return (m >> (padding_pos - 8)) == 0xFF


while True:
    c = int(input("c = "))
    print(check_padding(c))

```



### 競技中

なんかDownunderctfのRSA oracle iv とか sekaictfのEZmazeとかで見たことあるなぁと思いつつ

isufficientと同じ感じで格子組んでました...

```python
from sage.modules.free_module_integer import IntegerLattice
from pwn import *
from Crypto.Util.number import *
# Directly taken from rbtree's LLL repository
# From https://oddcoder.com/LOL-34c3/, https://hackmd.io/@hakatashi/B1OM7HFVI
def Babai_CVP(mat, target):
	M = IntegerLattice(mat, lll_reduce=True).reduced_basis
	G = M.gram_schmidt()[0]
	diff = target
	for i in reversed(range(G.nrows())):
		diff -=  M[i] * ((diff * G[i]) / (G[i] * G[i])).round()
	return target - diff


def solve(mat, lb, ub, weight = None):
	num_var  = mat.nrows()
	num_ineq = mat.ncols()

	max_element = 0 
	for i in range(num_var):
		for j in range(num_ineq):
			max_element = max(max_element, abs(mat[i, j]))

	if weight == None:
		weight = num_ineq * max_element

    # sanity checker
	if len(lb) != num_ineq:
		print("Fail: len(lb) != num_ineq")
		return

	if len(ub) != num_ineq:
		print("Fail: len(ub) != num_ineq")
		return

	for i in range(num_ineq):
		if lb[i] > ub[i]:
			print("Fail: lb[i] > ub[i] at index", i)
			return

    	# heuristic for number of solutions
	DET = 0

	if num_var == num_ineq:
		DET = abs(mat.det())
		num_sol = 1
		for i in range(num_ineq):
			num_sol *= (ub[i] - lb[i])
		if DET == 0:
			print("Zero Determinant")
		else:
			num_sol //= DET
			# + 1 added in for the sake of not making it zero...
			print("Expected Number of Solutions : ", num_sol + 1)

	# scaling process begins
	max_diff = max([ub[i] - lb[i] for i in range(num_ineq)])
	applied_weights = []

	for i in range(num_ineq):
		ineq_weight = weight if lb[i] == ub[i] else max_diff // (ub[i] - lb[i])
		applied_weights.append(ineq_weight)
		for j in range(num_var):
			mat[j, i] *= ineq_weight
		lb[i] *= ineq_weight
		ub[i] *= ineq_weight

	# Solve CVP
	target = vector([(lb[i] + ub[i]) // 2 for i in range(num_ineq)])
	result = Babai_CVP(mat, target)

	for i in range(num_ineq):
		if (lb[i] <= result[i] <= ub[i]) == False:
			print("Fail : inequality does not hold after solving")
			break
    
    	# recover x
	fin = None

	if DET != 0:
		mat = mat.transpose()
		fin = mat.solve_right(result)
	
	## recover your result
	return result, applied_weights, fin


while True:
    conn = remote('this-is-not-lsb.seccon.games', 8080)
    # conn = process(["python3","problem.py"])
    n = int(conn.recvline().decode().strip().split('n = ')[1])
    e = int(conn.recvline().decode().strip().split('e = ')[1])
    flag_length = int(conn.recvline().decode().strip().split('flag_length =')[1])
    c = int(conn.recvline().decode().strip().split('c = ')[1])

    print(n,e,c)
    print(flag_length)
    def query(c):
        conn.sendlineafter(b"c = ",str(c).encode())
        return eval( conn.recvline().decode())

    def blinded_query(r, c):
        return query((pow(r, e, n) * c) % n)



    rs_and_Us = []
    while len(rs_and_Us) < 50:
        r = randint(1, n)
        r_ = r
        if blinded_query(r, c):
            rs_and_Us.append([r, int(n).bit_length() - 2])
            print('got!', len(rs_and_Us))

    N = len(rs_and_Us)+1
    m = matrix(ZZ,N,N)

    for i in range(N-1):
        m[0,i+1] = rs_and_Us[i][0]

    for  i in range(N):
        m[i,i] = n
    m[0,0] = 1
    
    ub = [u for _,u in rs_and_Us]
    sol = solve(m,[0]*N, [flag_length]+ub)
    print(sol)
    sol = sol[0]

    print(sol)
    print(long_to_bytes(abs(sol)))
    conn.close()
    try:
        if "SECCON" in long_to_bytes(abs(sol)):
            exit()
        if sol > 2^flag_length:
            sol = -sol % n
            print(long_to_bytes(abs(sol)))
        if "SECCON" in long_to_bytes(abs(sol)):
                exit()
    except:
        continue
```

### upsolve
ただ、これだと求まらなかったので色々なupsolve拝見させてもらって得たアイディアを用いて組んで見ましたがどれもダメでした。。。(泣)
やっぱりLLLのお気持ちは難しいですねぇ...

これなら動きましたよ的なアドバイスあればお待ちしてます。。m(_ _)m

