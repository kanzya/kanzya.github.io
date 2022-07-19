---
title: 2022-07-18-usefull sage functions
author: kanon
date: 2022-07-18 00:00:00 + 0000
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

## number theory

### general

#### factorization 
sageには2通りの素因数分解の方法がある
どっちが何が得意かは知らんです。

##### nomal

特にoptionはなかった

[Factorizations](https://doc.sagemath.org/html/en/reference/structure/sage/structure/factorization.html#sage.structure.factorization.Factorization)

##### ecm

ecm.timeで時間見積もりができるので最初にしてもいいかも??

[楕円曲線因数分解法](https://doc.sagemath.org/html/en/reference/interfaces/sage/interfaces/ecm.html#:~:text=The ECM.factor () method is an example for,factorization method. See http%3A%2F%2Fecm.gforge.inria.fr for more about GMP-ECM.)

```python
from sage.all import *

factor(n)
ecm.factor(n)

ecm.time(n, factor_digits, verbose=False)
```

#### nth roots

[超参考になる文献](https://doc.sagemath.org/html/en/reference/finite_rings/sage/rings/finite_rings/integer_mod.html)

どれも素体でも整数上でも使える

##### nth_roots

**公式ドキュメントによれば拡大体では扱えない(extend オプション付けなくてもできたけど...謎)**

　=> all=Trueにすると回避できる　（意味わからん...）
2べきは出来ないのでHensel's liftで対応できる

options:

-  all => 全て答えを出すか否か

```python
from sage.all import *

# 整数上
100.nth_root(3) # 100 is not a 3rd power
100.nth_root(2) # 10

# galios field
K = GF(31)
K(22).nth_root(7) # 13
K(13)^7 ==22 # True

# extension field power of 2

K = Zmod(2^64)
K(9195003341624157505).nth_root(2, all=True)
#[16186113672519655585,
# 2260630401189896031,
# 6962741635664879777,
# 11484002438044671839]

# extension field power of odd prime

K = Zmod(690712633549859897233^5)
K(231473674144484896672).nth_root(2, all=True)

#[103359036724125012493766467500976355473507164707367245178497331640836743394263210309787932894341317859638,
# 53853435766687674235431903782586896799630993814437811803467099256085100620840045707544229492305838681755]

```

##### .sqrt

使い方は[nth_root](#.nth_roots)と同じ


```python
K = Zmod(690712633549859897233^5)
a = K(231473674144484896672)
K(231473674144484896672).sqrt(all=True)
#[53853435766687674235431903782586896799630993814437811803467099256085100620840045707544229492305838681755,103359036724125012493766467500976355473507164707367245178497331640836743394263210309787932894341317859638]
```

### Polynominal Ring


#### roots
多項式の範囲指定した中の解の探索

```python
from sage.all import *
R.<x> = QQ[]
f = (x+17)*(x-3)*(x-1/8)^3

find_root(f, 0,4) #2.999999999999995
# abs tol 1e-6 (note -- precision of answer isn't very good on some machines)
find_root(f, 0,1) #0.124999
find_root(f, -20,-10) #-17.0
```