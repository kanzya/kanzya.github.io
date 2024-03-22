---
title: buckeye CTF 2022 writeup
author: kanon
date: 2022-11-07 09:00:00 +0800
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

Nu1L ctf でpocかけなくて撃沈。。。

## \[crypto\] megaxord [312 solve]

### chall

bytesのファイルのみ

### solve

順に探索して終わり

```python
def bxor(a,b):
    return bytes([_a^b for _a in a])

f = open("megaxord.txt","rb").read()
for i in range(256):
    if b"buckeye{" in bxor(f,i):
        for x in bxor(f,i).decode().split(" "):
            if "buckeye{" in x:
                print(x)
                exit()
                
# buckeye{m1gh7y_m0rph1n_w1k1p3d14_p4g3}

```

## \[crypto\] Twin prime RSA [ 167 solve]

### chall

```python
import Crypto.Util.number as cun

while True:
    p = cun.getPrime(1024)
    q = p + 2
    if cun.isPrime(q):
        break

n = p * q
e = 0x10001

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

FLAG = cun.bytes_to_long(b"buckeye{?????????????????????????????????????????????????????????????}")
c = pow(FLAG, e, n)
assert pow(c, d, n) == FLAG

print(f"n = {n}")
print(f"c = {c}")

"""
Output:
n = 20533399299284046407152274475522745923283591903629216665466681244661861027880216166964852978814704027358924774069979198482663918558879261797088553574047636844159464121768608175714873124295229878522675023466237857225661926774702979798551750309684476976554834230347142759081215035149669103794924363457550850440361924025082209825719098354441551136155027595133340008342692528728873735431246211817473149248612211855694673577982306745037500773163685214470693140137016315200758901157509673924502424670615994172505880392905070519517106559166983348001234935249845356370668287645995124995860261320985775368962065090997084944099
c = 786123694350217613420313407294137121273953981175658824882888687283151735932871244753555819887540529041840742886520261787648142436608167319514110333719357956484673762064620994173170215240263058130922197851796707601800496856305685009993213962693756446220993902080712028435244942470308340720456376316275003977039668016451819131782632341820581015325003092492069871323355309000284063294110529153447327709512977864276348652515295180247259350909773087471373364843420431252702944732151752621175150127680750965262717903714333291284769504539327086686569274889570781333862369765692348049615663405291481875379224057249719713021
"""

```

### solve

二次方程式組み立てて$p,q$求めて終わり\\
最近グレブナーでサボってたから真面目にやりましたまる...

```python
from  Crypto.Util.number import *
from gmpy2 import iroot
n = 20533399299284046407152274475522745923283591903629216665466681244661861027880216166964852978814704027358924774069979198482663918558879261797088553574047636844159464121768608175714873124295229878522675023466237857225661926774702979798551750309684476976554834230347142759081215035149669103794924363457550850440361924025082209825719098354441551136155027595133340008342692528728873735431246211817473149248612211855694673577982306745037500773163685214470693140137016315200758901157509673924502424670615994172505880392905070519517106559166983348001234935249845356370668287645995124995860261320985775368962065090997084944099
c = 786123694350217613420313407294137121273953981175658824882888687283151735932871244753555819887540529041840742886520261787648142436608167319514110333719357956484673762064620994173170215240263058130922197851796707601800496856305685009993213962693756446220993902080712028435244942470308340720456376316275003977039668016451819131782632341820581015325003092492069871323355309000284063294110529153447327709512977864276348652515295180247259350909773087471373364843420431252702944732151752621175150127680750965262717903714333291284769504539327086686569274889570781333862369765692348049615663405291481875379224057249719713021

p = (-2+iroot(4+4*n,2)[0])//2
q =n//p

assert n == p*q

phi = (p-1)*(q-1)
e = 0x10001
print(long_to_bytes(pow(c, pow(e,-1,phi), n)))
# buckeye{B3_TH3R3_OR_B3_SQU4R3__abcdefghijklmonpqrstuvwxyz__0123456789}
```

## \[crypto\] fastfor [ 111 solve]

### chall

```python
from PIL import Image
import numpy

def check_hash(fi):
    image = numpy.asarray(Image.open('static/IMG.png'))
    submission = numpy.asarray(Image.open(fi))
    if image.shape != submission.shape:
        return False
    same = numpy.bitwise_xor(image, submission)
    if (numpy.sum(same) == 0):
        return False
    im_alt = numpy.fft.fftn(image)
    in_alt = numpy.fft.fftn(submission)
    im_hash = numpy.std(im_alt)
    in_hash = numpy.std(in_alt)
    if im_hash - in_hash < 1 and im_hash - in_hash > -1:
        return True
    return False

```

### solve

2つの画像の入力から近い標準偏差の値を求めろらしいです。\\
お試し感覚でIMG.pngの0,0チャンクの値を+1したものを突っ込んだらフラグ出た...

```python
import check_hash
from PIL import Image

img2 = Image.open('static/IMG.png')

img2.putpixel((0,0),(159, 227, 255, 118))
img2.save("test.png")

print(check_hash.check_hash("test.png"))
# buckeye{D33p_w0Rk_N07_WhY_574ND4RD_d3V}

```

## \[crypto\] powerball [ 78 solve]

### chall

```javascript
import express from 'express'
import http from 'http'
import { Server } from 'socket.io'
import crypto from 'crypto'

function nextRandomNumber () {
  return (multiplier * seed) % modulus
}

function areArraysEqual (a, b) {
  return (
    a.length === b.length &&
    a.every((x, i) => {
      return x === b[i]
    })
  )
}

function seedToBalls (n) {
  const balls = []
  for (let i = 0; i < 10; i++) {
    balls.push(Number(n % 100n))
    n = n / 100n
  }
  return balls
}

const app = express()
app.use(express.static('static'))

const server = http.createServer(app)
const io = new Server(server)

const modulus = crypto.generatePrimeSync(128, { safe: true, bigint: true })
const multiplier = (2n ** 127n) - 1n
let seed = 2n
for (let i = 0; i < 1024; i++) {
  seed = nextRandomNumber()
}
let winningBalls = seedToBalls(seed)
let lastLotteryTime = Date.now()

setInterval(() => {
  seed = nextRandomNumber()
  winningBalls = seedToBalls(seed)
  lastLotteryTime = Date.now()
}, 60 * 1000)

io.on('connection', (socket) => {
  socket.ticket = { balls: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0], submissionTime: 0 }
  
  socket.on('updateRequest', () => {
    let flag = ''

    if (
      areArraysEqual(socket.ticket.balls, winningBalls) &&
      socket.ticket.submissionTime < lastLotteryTime
    ) {
      flag = process.env.FLAG
    }

    socket.emit('update', {
      last_winning_seed: seed.toString(),
      flag: flag
    })
  })

  socket.on('submitBalls', (balls) => {
    if (!(Array.isArray(balls) && balls.length === 10)) return
    for (let i = 0; i < 10; i++) {
      if (typeof balls[i] !== 'number') return
    }

    socket.ticket = { balls: balls, submissionTime: Date.now() }
    
  })
})

server.listen(3000, () => {
  console.log('Ready')
})


```
{: file="app.js" }

```javascript
const socket = io() // eslint-disable-line no-undef
let seenFlag = false

function seedToBalls (n) {
  const balls = []
  for (let i = 0; i < 10; i++) {
    balls.push(Number(n % 100n))
    n = n / 100n
  }
  return balls
}

function handleUpdate (update) {
  console.log(update)

  if (update.flag && !seenFlag) {
    alert(update.flag)
    seenFlag = true
  }

  const balls = seedToBalls(BigInt(update.last_winning_seed))
  for (let i = 0; i < 10; i++) {
    document.getElementById(`ball${i}`).innerText = balls[i]
  }
}

function initSocket () {
  socket.on('update', handleUpdate)
  socket.emit('updateRequest')

  setInterval(() => {
    console.log(Date.now() / 1000)
    socket.emit('updateRequest')
  }, 5000)
}

function sendBallsIfAvailable () {
  const balls = []
  for (let i = 0; i < 10; i++) {
    const a = parseInt(document.getElementById(`input-ball${i}`).value)
    if (isNaN(a) || a < 0 || a >= 100) return
    balls.push(a)
  }
  console.log(`Submitting balls ${balls}`)
  socket.emit('submitBalls', balls)
}

function initInput () {
  for (let i = 0; i < 10; i++) {
    document.getElementById(`input-ball${i}`).onkeypress = (event) => {
      const n = parseInt(event.key)
      if (isNaN(n)) return false
      setTimeout(sendBallsIfAvailable, 100)
    }
    document.getElementById(`input-ball${i}`).onpaste = (event) => {
      const n = event.clipboardData.getData('Text')
      if (isNaN(n)) return false
      setTimeout(sendBallsIfAvailable, 100)
    }
  }
}

initSocket()
initInput()

```
{: file="main.js" }

### solve

個人的にはnode jsの仕様を理解するのに時間がかかった...(console.log使えると思ってなくてこれがeasyなわけないやろとか思ってたとか、思ってなかったとかorz)

クライアント側で動いているのはmain.jsなのでconsole.logからupdate.last_winning_seedを求めることができる。\\
よって二項間漸化式$ball_{n+1} \equiv a*ball_n \pmod p$から$p$の値が求まる。
この問題の目標として、画面に表示されている乱数よりも後の乱数を求めて入力する必要があるので、今が何項目か調べてやればOK

```python
from sage.all import *
from Crypto.Util.number import *

def int_to_ball(a):
    ret = []
    for i in range(10):
        # print(a%100)
        ret.append(a%100)
        a = a//100
    return ret[::-1]

a = 2**127 -1
s1 = 38386045261155976433540741815806908550
s2 = 43312535513384515088100925378630654634
s3 = 201038737730550603713123190637463026163

nowball = 76544625579486203475251392218240548059

p = factor(gcd(s2*a-s3,s1*a-s2))[-1][0]

nowball = GF(p)(nowball)
win = GF(p)(2)
a = GF(p)(a)

for i in range(2**26):
    if int(win)==int(nowball):
        print(int_to_ball(int(win))[::-1])
        win =  win*a
        print(int_to_ball(int(win))[::-1])
        win =  win*a
        print(int_to_ball(int(win))[::-1])
        win =  win*a
        print(int_to_ball(int(win))[::-1])
        break
    win = win*a
# buckeye{y3ah_m4yb3_u51nG_A_l1N34r_c0nGru3Nt1al_G3n3r4t0r_f0r_P0w3rB4lL_wA5nt_tH3_b3st_1d3A}
```


## \[crypto\] bounce [ 97 solve]

### chall

```python
import random

with open('sample.txt') as file:
    line = file.read()

with open('flag.txt') as file:
    flag = file.read()

samples = [line[i:i+28] for i in range(0, len(line) - 1 - 28, 28)]

samples.insert(random.randint(0, len(samples) - 1), flag)

i = 0
while len(samples) < 40:
    samples.append(samples[len(samples) - i - 2])
    i = random.randint(0, len(samples) - 1)

encrypted = []
for i in range(len(samples)):
    x = samples[i]
    if i < 10:
        nonce = str(i) * 28
    else:
        nonce = str(i) * 14
    encrypted.append(''.join(str(ord(a) ^ ord(b)) + ' ' for a,b in zip(x, nonce)))

with open('output.txt', 'w') as file:
    for i in range(0, 4):
        file.write('input: ' + samples[i] + '\noutput: ' + encrypted[i] + '\n')
    file.write('\n')
    for i in range(4, len(samples)):
        file.write('\ninput: ???\n' + 'output: ' + encrypted[i])

```


### solve

そのまま突っ込んで終わり...


```python
f = open("output.txt").readlines()

part1_input = [f[i][7:-1] for i in range(0,8,2)]
part1_output = [[ k for k in  f[i+1][8:-2].split(" ") ]for i in range(0,8,2)]

part2_output = [[ int(k) for k in  f[i+1][8:-2].split(" ") ]for i in range(10,len(f),2)]
output = part1_output+part2_output

for i in range(len(output)):
    x = output[i]
    if i < 10:
        nonce = str(i) * 28
    else:
        nonce = str(i) * 14
    if "eye" in ''.join(chr(int(a) ^ ord(b)) for a,b in zip(x, nonce)):
        print(''.join(chr(int(a) ^ ord(b)) for a,b in zip(x, nonce)))

# buckeye{some_say_somefish:)}
```

## \[crypto\] SSSHIT [ 41 solve]

### cahll

```python
import Crypto.Util.number as cun
import random
import ast


def evaluate_polynomial(polynomial: list, x: int, p: int):
    return (
        sum(
            (coefficient * pow(x, i, p)) % p for i, coefficient in enumerate(polynomial)
        )
        % p
    )


N_SHARES = 3


def main():
    print(
        f"I wrote down a list of people who are allowed to get the flag and split it into {N_SHARES} using Shamir's Secret Sharing."
    )
    MESSAGE = cun.bytes_to_long(b"qxxxb, BuckeyeCTF admins, and NOT YOU")

    p = cun.getPrime(512)

    polynomial = [MESSAGE] + [random.randrange(1, p) for _ in range(N_SHARES - 1)]
    points = [(i, evaluate_polynomial(polynomial, i, p)) for i in range(1, N_SHARES + 1)]

    print("Your share is:")
    print(points[0])
    print("The other shares are:")
    for i in range(1, len(points)):
        print(points[i])

    print()
    print("Now submit your share for reconstruction:")
    your_input = ast.literal_eval(input(">>> "))
    if (
        type(your_input) is not tuple
        or len(your_input) != 2
        or type(your_input[0]) is not int
        or type(your_input[1]) is not int
        or your_input[0] != 1
        or not (0 <= your_input[1] < p)
    ):
        print("Bad input")
        return

    points[0] = your_input

    xs = [point[0] for point in points]
    ys = [point[1] for point in points]

    y_intercept = 0
    for j in range(N_SHARES):
        product = 1
        for i in range(N_SHARES):
            if i != j:
                product = (product * xs[i] * pow(xs[i] - xs[j], -1, p)) % p
        y_intercept = (y_intercept + ys[j] * product) % p

    reconstructed_message = cun.long_to_bytes(y_intercept)
    if reconstructed_message == b"qxxxb, BuckeyeCTF admins, and ME":
        print("Here's your flag:")
        print("buckeye{?????????????????????????????????????????}")
    else:
        print(f"Sorry, only these people can see the flag: {reconstructed_message}")


main()

```

### solve

2つの乱数を$r_1,r_2$とし、メッセージを$m$とすると最初の多項式の部分で$points_i = i^{2} \*r_2 + i\*r_1 + m \pmod p, (1 \leq i\leq 3)$を求めているが、それぞれのpointsの値はわかるのでそれをうまく用いることで$p$を復元でき、そこから$r_1,r_2$を求められる。\\
暗号を求めている部分を関数として、入力に、$points_i,i$を与え$f(points_1,points_2,points_3,1,2,3)$とできる。\\
ここで$points_1$はこちらで指定できる任意の値で出力として"qxxxb, BuckeyeCTF admins, and ME"を出すように変化させてやればOK

```python
from pwn import *
from Crypto.Util.number import *
from sage.all import *

io = remote("pwn.chall.pwnoh.io" ,13382)
# io = process(["python3","chall.py"])

#295 bit
MESSAGE = bytes_to_long(b"qxxxb, BuckeyeCTF admins, and NOT YOU")
#255 bit
reconstructed_message = bytes_to_long(b"qxxxb, BuckeyeCTF admins, and ME")

def recover(points):
    y = points[1]
    p = factor(y[2]-3*y[1]+3*y[0]-MESSAGE)[-1][0]
    assert int(p).bit_length() == 512
    return p

def catch():
    points = [[],[]]

    io.recvline()
    io.recvline()
    p = eval(io.recvline().decode())
    points[0].append(p[0])
    points[1].append(p[1])
    io.recvline()
    p = eval(io.recvline().decode())
    points[0].append(p[0])
    points[1].append(p[1])
    p = eval(io.recvline().decode())
    points[0].append(p[0])
    points[1].append(p[1])
    return points

def calc(points,p):
    N_SHARES = 3
    
    xs =  points[0]
    y = [0]+points[1][1:]
    
    pro = 0
    pro += (xs[0]*pow(xs[0]-xs[1],-1,p)*xs[2]*pow(xs[2]-xs[1],-1,p)*y[1])%p
    pro += (xs[0]*pow(xs[0]-xs[2],-1,p)*xs[1]*pow(xs[1]-xs[2],-1,p)*y[2])%p
    y0 = ((reconstructed_message - pro)*pow(xs[1]*pow(xs[1]-xs[0],-1,p)*xs[2]*pow(xs[2]-xs[0],-1,p),-1,p))%p
    return y0

points = catch()
p = recover(points)
io.recvuntil(b"> ")
y0 = calc(points,int(p))

io.sendline(f"(1,{y0})".encode())
io.interactive()

# buckeye{tH1s_SSS_sch3Me_c0uLd_u5e_s0M3_S1gna7Ur3s}
```

## \[crypto\] Quad prime RSA [ 23 solve]

### chall

```python
import Crypto.Util.number as cun

p = cun.getPrime(500)

while True:
    q = cun.getPrime(1024)
    r = q + 2
    if cun.isPrime(r):
        break

s = cun.getPrime(500)

n_1 = p * q
n_2 = r * s

e = 0x10001
d_1 = pow(e, -1, (p - 1) * (q - 1))
d_2 = pow(e, -1, (r - 1) * (s - 1))

FLAG = cun.bytes_to_long(b"buckeye{??????????????????????????????????????????????????????????????????????}")
c_1 = pow(FLAG, e, n_1)
c_2 = pow(FLAG, e, n_2)

assert pow(c_1, d_1, n_1) == FLAG
assert pow(c_2, d_2, n_2) == FLAG

print(f"n_1 = {n_1}")
print(f"n_2 = {n_2}")
print(f"c_1 = {c_1}")
print(f"c_2 = {c_2}")

"""
Output:
n_1 = 266809852588733960459210318535250490646048889879697803536547660295087424359820779393976863451605416209176605481092531427192244973818234584061601217275078124718647321303964372896579957241113145579972808278278954608305998030194591242728217565848616966569801983277471847623203839020048073235167290935033271661610383018423844098359553953309688771947405287750041234094613661142637202385185625562764531598181575409886288022595766239130646497218870729009410265665829
n_2 = 162770846172885672505993228924251587431051775841565579480252122266243384175644690129464185536426728823192871786769211412433986353757591946187394062238803937937524976383127543836820456373694506989663214797187169128841031021336535634504223477214378608536361140638630991101913240067113567904312920613401666068950970122803021942481265722772361891864873983041773234556100403992691699285653231918785862716655788924038111988473048448673976046224094362806858968008487
c_1 = 90243321527163164575722946503445690135626837887766380005026598963525611082629588259043528354383070032618085575636289795060005774441837004810039660583249401985643699988528916121171012387628009911281488352017086413266142218347595202655520785983898726521147649511514605526530453492704620682385035589372309167596680748613367540630010472990992841612002290955856795391675078590923226942740904916328445733366136324856838559878439853270981280663438572276140821766675
c_2 = 111865944388540159344684580970835443272640009631057414995719169861041593608923140554694111747472197286678983843168454212069104647887527000991524146682409315180715780457557700493081056739716146976966937495267984697028049475057119331806957301969226229338060723647914756122358633650004303172354762801649731430086958723739208772319851985827240696923727433786288252812973287292760047908273858438900952295134716468135711755633215412069818249559715918812691433192840
"""

```


### solve

少し式変形してやると$n_1 = p\*q, n_2 = (q+2)\*r $となり少し展開して$n_1 = p\*q, n_2 = q\*r + 2\*r $これは$n_i = p_i\*q + r_i$の形で表せれられるので、Approximate GCD Problemと見て解くことができます...scriptは[これ](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/acd/ol.py)を使いました。便利...!!\\
実際は連分数を想定していたそう...???なるほど...

```python
n_1 = 266809852588733960459210318535250490646048889879697803536547660295087424359820779393976863451605416209176605481092531427192244973818234584061601217275078124718647321303964372896579957241113145579972808278278954608305998030194591242728217565848616966569801983277471847623203839020048073235167290935033271661610383018423844098359553953309688771947405287750041234094613661142637202385185625562764531598181575409886288022595766239130646497218870729009410265665829
n_2 = 162770846172885672505993228924251587431051775841565579480252122266243384175644690129464185536426728823192871786769211412433986353757591946187394062238803937937524976383127543836820456373694506989663214797187169128841031021336535634504223477214378608536361140638630991101913240067113567904312920613401666068950970122803021942481265722772361891864873983041773234556100403992691699285653231918785862716655788924038111988473048448673976046224094362806858968008487
c_1 = 90243321527163164575722946503445690135626837887766380005026598963525611082629588259043528354383070032618085575636289795060005774441837004810039660583249401985643699988528916121171012387628009911281488352017086413266142218347595202655520785983898726521147649511514605526530453492704620682385035589372309167596680748613367540630010472990992841612002290955856795391675078590923226942740904916328445733366136324856838559878439853270981280663438572276140821766675
c_2 = 111865944388540159344684580970835443272640009631057414995719169861041593608923140554694111747472197286678983843168454212069104647887527000991524146682409315180715780457557700493081056739716146976966937495267984697028049475057119331806957301969226229338060723647914756122358633650004303172354762801649731430086958723739208772319851985827240696923727433786288252812973287292760047908273858438900952295134716468135711755633215412069818249559715918812691433192840
from Crypto.Util.number import *
# n1 = q*p + 0*s
# n2 = (q+2)+r = q*s + 2*s

# I use https://github.com/jvdsn/crypto-attacks/blob/master/attacks/acd/ol.py
def attack(x, rho):
    """
    Solves the ACD problem using the orthogonal based approach.
    More information: Galbraith D. S. et al., "Algorithms for the Approximate Common Divisor Problem" (Section 4)
    :param x: the x samples, with xi = p * qi + ri
    :param rho: the bit length of the r values
    :return: the secret integer p and a list containing the r values, or None if p could not be found
    """
    def symmetric_mod(x, m):
        """
        Computes the symmetric modular reduction.
        :param x: the number to reduce
        :param m: the modulus
        :return: x reduced in the interval [-m/2, m/2]
        """
        return int((x + m + m // 2) % m) - int(m // 2)
    
    assert len(x) >= 2, "At least two x values are required."

    R = 2 ** rho

    B = matrix(ZZ, len(x), len(x) + 1)
    for i, xi in enumerate(x):
        B[i, 0] = xi
        B[i, i + 1] = R

    B = B.LLL()

    K = B.submatrix(row=0, col=1, nrows=len(x) - 1, ncols=len(x)).right_kernel()
    q = K.an_element()
    r0 = symmetric_mod(x[0], q[0])
    p = abs((x[0] - r0) // q[0])
    r = [symmetric_mod(xi, p) for xi in x]
    if all(-R < ri < R for ri in r):
        return int(p), r
    
q,s = attack([n_1,n_2], 513)
p = n_1//q

phi = (p-1)*(q-1)
e = 0x10001
print(long_to_bytes(int(pow(c_1, pow(e,-1,phi), n_1))))

# buckeye{I_h0p3_y0u_us3D_c0nt1nu3d_fr4ct10Ns...th4nk5_d0R5A_f0r_th3_1nsp1r4t10n}


```