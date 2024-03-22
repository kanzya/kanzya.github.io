---
title: 2022-07-18-usefull sage functions
author: kanon
date: 2100-07-18 00:00:00 + 0000
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


## Cryptosystem(KEM)


### RSA暗号

encryptとdecryptは省略

#### technique・code

##### $n$がいくつかの素数に素因数分解できた時、各素数での離散対数を求めCRTで復元

$$
c = m^x \ mod \prod_{i}{p_i} \
$$

 

```python
# sage code 
def find_dislog(p,y,g):
    
    G = GF(p)
    g = G(g)
    y = G(y)
    
    x = discrete_log(y,g)
    assert g^x==y
    # print(x)
    return x
    
# Pohlig–Hellman法
def RSA_with_CRT(g, y, p_fac):
    crt_moduli = []
    crt_remain = []
    for q in p_fac:
        x = find_dislog(q,y, g)
        if (x is None) or (x <= 1):
            continue
        crt_moduli.append(GF(q)(g).multiplicative_order())
        crt_remain.append(x)
        print(x)
    x = crt(crt_remain, crt_moduli)
    return x

```

$e,y$がわかっているときに$x$の復元
$$
y = x^e \ mod \prod_{i}{p_i} \
$$

```python
# sage code 
def find_base(y,e,n_fac):
    from functools import reduce
    from operator import mul
    phi_fac = []
    e_fac = []
    n = reduce(mul, n_fac)
    
    for n_f in n_fac:
        Z = Zmod(euler_phi(n_f))
        phi_fac.append(euler_phi(n_f))
        e_fac.append(int(Z(e)^(-1)))
    e_inv = crt(e_fac,phi_fac)
    x = pow(c_1,int(e_inv),n)
    print(pow(x,e,n),  y)
    return x
x = find_base(y,e,n_fac)
```



### Paillier暗号

$$
(1+N)^M = 1 + MN \  mod \  N^2
$$

以上の性質を用いて暗号の構築をしている(証明は以下)
$$
\begin{eqnarray}
(1+N)^M &=& \sum_{i=0}^{M}{}_MC_iN^i \ mod \ N^2 \\
&=& 1+{}_MC_1N^1+\sum_{i=2}^{M}{}_MC_iN^i \ mod \ N^2 \\
&=& 1+{}_MC_1N^1 \ mod \ N^2 \\
\end{eqnarray}
$$

#### keygen

1. 二つの大きな素数$p,q$をランダムに選び、$n = pq$とする。
2. $k  \leq Z_n$を任意に選び、$g = 1+kn \ mod \ N^2$とする。
3. $pk = (n,g)$と $sk = (p,q)$ を出力する。
4. 

#### encrypt

$Z_n$ の元 $m$ を暗号化するには以下のようにする。

1. $ \mathbb {Z} _{n^{2}}^{*}$からランダムに $r$ を選ぶ。
2. $c=g^{m}\cdot r^{n}{\bmod {n}}^{2}$が暗号文である。

#### decrypt

1. 暗号文$c\in \mathbb {Z} _{n^{2}}^{*}$ を復号するには $λ = lcm(p − 1, q − 1)$ とし、
   - $m=L(c^{\lambda }\mod n^{2})/L(g^{\lambda }\mod n^{2}){\bmod {n}}$を出力する。



#### 性質

平文の加法準同型性が成立

