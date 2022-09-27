---
title: manger attackについて
author: kanon
date: 2022-09-26 14:30:00 +0800
categories: [ctf]
tags: [ctf,cryptography]
math: true
mermaid: true
# image:
#   path: /commons/devices-mockup.png
#   width: 800
#   height: 500
#   alt: Responsive rendering of Chirpy theme on multiple devices.
---

# 初めに
DownUnderCTF で rsa-interval-oracle が出題された。

主な解法は以下に纏められるし、[公式解説](https://github.com/DownUnderCTF/Challenges_2022_Public/blob/main/crypto/rsa-interval-oracle-iii/solve/WRITEUP.md)でも同じようなことが書いてある。

- rsa-interval-oracle-i   →　bitごとの復号 or LSB oracle attack
- rsa-interval-oracle-ii  →　Manger attack or LSB oracle attack
- rsa-interval-oracle-iii →　EHNP(HNP) or LSB oracle attack
- rsa-interval-oracle-iv  →　EHNP(HNP)

## ソースコード(参考)
rsa-interval-oracle-iv のソースコード

```python
#!/usr/bin/env python3

import signal, time
from os import urandom, path
from Crypto.Util.number import getPrime, bytes_to_long


FLAG = open(path.join(path.dirname(__file__), 'flag.txt'), 'r').read().strip()

N_BITS = 384
TIMEOUT = 3 * 60
MAX_INTERVALS = 4
MAX_QUERIES = 4700


def main():
    p, q = getPrime(N_BITS//2), getPrime(N_BITS//2)
    N = p * q
    e = 0x10001
    d = pow(e, -1, (p - 1) * (q - 1))

    secret = bytes_to_long(urandom(N_BITS//9))
    c = pow(secret, e, N)

    print(N)
    print(c)

    intervals = [(0, 2**(N_BITS - 11)), (0, 2**(N_BITS - 10)), (0, 2**(N_BITS - 9)), (0, 2**(N_BITS - 8))]
    queries_used = 0

    while True:
        print('1. Add interval\n2. Request oracle\n3. Get flag')
        choice = int(input('> '))

        if choice == 1:
            if len(intervals) >= MAX_INTERVALS:
                print('No more intervals allowed!')
                continue

            lower = int(input(f'Lower bound: '))
            upper = int(input(f'Upper bound: '))
            intervals.insert(0, (lower, upper))

        elif choice == 2:
            if queries_used > 0:
                print('No more queries allowed!')
                continue

            queries = input('queries: ')
            queries = [int(c.strip()) for c in queries.split(',')]
            queries_used += len(queries)
            if queries_used > MAX_QUERIES:
                print('No more queries allowed!')
                continue

            results = []
            for c in queries:
                m = pow(c, d, N)
                for i, (lower, upper) in enumerate(intervals):
                    in_interval = lower < m < upper
                    if in_interval:
                        results.append(i)
                        break
                else:
                    results.append(-1)

            print(','.join(map(str, results)), flush=True)

        elif choice == 3:
            secret_guess = int(input('Enter secret: '))
            if secret == secret_guess:
                print(FLAG)
            else:
                print('Incorrect secret :(')
            exit()

        else:
            print('Invalid choice')


if __name__ == '__main__':
    signal.alarm(TIMEOUT)
    main()

```


# 問題点
問題となるのは *choice == 1* の指定数と *choice == 2* の応答時間である。

|  問題  |  難点  |
| ---- | ---- |
|  i  |  なし  |
|  ii  |  クエリが1つ  |
|  iii  |  応答時間が長い・ クエリが4つ |
|  iv  |  クエリが4つ指定 ,1回で全て送信 |

公式解説でiii,ivは詳しく解説されているのでここでは、ii の manger attack について軽く解説したいと思います。

> 現時点での私が理解したものを書き綴っているため、一部誤解している可能性もあります。その場合、指摘してくださるとありがたいです。
{: .prompt-warning }


# manger attack とは

ii の攻撃にある Manger’s attack とは
Manger さんが2001年に出した[論文](https://www.iacr.org/archive/crypto2001/21390229.pdf)に起因して Manger attack と呼ばれます。
これは、OAEPというパディングに対する攻撃に用いられるそうですが、ここでは内容をメインでするため省略します。

## 攻撃手法の要約

### STEP1 
解の範囲を大まかに絞る。(2分探索)
![STEP1-1](https://github.com/kanzya/photo/raw/main/1.png)
2枚目

![STEP1-2](https://github.com/kanzya/photo/raw/main/1-1.png)

### STEP2 
mの存在範囲を $[iN,iN+2B)$ に移動・拡大or縮小する。
![STEP2](https://github.com/kanzya/photo/raw/main/2.png)


### STEP3
oracleで判定し二分探索する。
二分探索後は範囲の場所である $[iN,iN+2B)$ を満たさない。よって3.3で求める$f_{tmp}$で最小値と最大値の差を$2B$にするように範囲の縮尺を拡大する。次に、$f_3$において平行移動を行い最小値を $iN$ のところまでにする。
結果として、oracleの$B$以上か以下かの判定をうまく用いることができる。
これを繰り返し、min と max の値が同じになれば終了し min が答えの$m$となる
![STEP3](https://github.com/kanzya/photo/raw/main/3.png)



ここで、rsa-interval-oracle の値設定は $N = 2^{348}$ よりmanger attack を使用する際の $B$ の値は$B = 2^{( \lceil \log_{256} N \rceil-1)}=376$となる。よってiiのバージョンにおいて、クエリに376を投げてやれば manger attack が成立でき flag を得ることができる。



誤字・脱字・訂正等ありましたら、twitterでお知らせください…