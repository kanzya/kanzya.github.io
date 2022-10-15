---
title: ASIS CTF writeup
author: kanon
date: 2022-10-15 14:59:00 +0800
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

ASISです。祭りと被って死ぬかと思いましたまる。。

## \[crypto\] Binned　[148 solve]

### chall

```python
#!/usr/bin/env python3

from Crypto.Util.number import *
from gensafeprime import *
from flag import flag

def keygen(nbit):
	p, q = [generate(nbit) for _ in range(2)]
	return (p, q)

def encrypt(m, pubkey):
	return pow(pubkey + 1, m, pubkey ** 3)

p, q = keygen(512)
n = p * q

flag = bytes_to_long(flag)
enc = encrypt(flag, n)

print(f'pubkey = {n}')
print(f'enc = {enc}')
```

{: file="binned.py" }



### solve

encryptで$enc = (pubkey+1)^m \pmod {pubkey^3}$ で暗号されているので式変形を施す。
$$
enc =(pub+1)^m \pmod {pub^3} \\
= \sum_{i=0}^m  \ _m C_i(pub^i+1^{m-i}) \pmod {pub^3}\\
= 1 +m*pub + \frac{m*(m-1)}{2}pub^2\\
$$
となるので、方程式を解いてやれば$m$が求まる。



```python
from Crypto.Util.number import *

pubkey = 125004899806380680278294077957993138206121343727674199724251084023100054797391533591150992663742497532376954423241741439218367086541339504325939051995057848301514908377941815605487168789148131591458301036686411659334843972203243490288676763861925647147178902977362125434420265824374952540259396010995154324589
enc = 789849126571263315208956108629196540107771075292285804732934458641661099043398300667318883764744131397353851782194467024270666326116745519739176492710750437625345677766980300328542459318943175684941281413218985938348407537978884988013947538034827562329111515306723274989323212194585378159386585826998838542734955059450048745917640814983343040930383529332576453845724747105810109832978045135562492851617884175410194781236450629682032219153517122695586503298477875749138129517477339813480115293124316913331705913455692462482942654717828006590051944205639923326375814299624264826939725890226430388059890231323791398412019416647826367964048142887158552454494856771139750458462334678907791079639005383932256589768726730285409763583606927779418528562990619985840033479201147509241313757191997545174262930707521451438204766627975109619779824255444258160

PR.<m,n> = QQ[]
polys = [
    2*m*n  + (m^2 - m )*n*n - 2 *(enc -1) ,
    pubkey - n,
]
I = Ideal(polys)
ans = I.variety(ring=ZZ)[0]
print(ans)
m, n = ans[m], ans[n]

print(long_to_bytes(m))
```

{: file="solve.py" }



## [crypto] Chaffymasking　[61 solve]

### chall

```python
#!/usr/bin/env python3

import numpy as np
import binascii
import os, sys
from flag import FLAG

def die(*args):
	pr(*args)
	quit()

def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()

def sc(): 
	return sys.stdin.buffer.readline()

def pad(inp, length):
	result = inp + os.urandom(length - len(inp))
	return result

def byte_xor(a, b):
	return bytes(_a ^ _b for _a,_b in zip(a,b)) 

def chaffy_mask(salt, LTC, m, n):
	q = n ** 2
	half1_salt = salt[:m // 8]
	half2_salt = salt[m // 8:]
	xor_salts = int.from_bytes(byte_xor(half1_salt, half2_salt), "big")

	if xor_salts == 0:
		half1_salt = byte_xor(half1_salt, os.urandom(m))
	half1_binStr = "{:08b}".format(int(half1_salt.hex(),16))
	if(len(half1_binStr) < m):
		half1_binStr = "0" * (m - len(half1_binStr)%m) + half1_binStr
	half2_binStr = "{:08b}".format(int(half2_salt.hex(),16))
	if(len(half2_binStr) < m):
		half2_binStr = "0" * (m - len(half2_binStr)%m) + half2_binStr
	
	vec_1 = np.array(list(half1_binStr), dtype=int)
	vec_1 = np.reshape(vec_1, (m,1))
	vec_2 = np.array(list(half2_binStr), dtype=int)
	vec_2 = np.reshape(vec_2, (m,1))
	
	out_1 = LTC.dot(vec_1) % q
	out_2 = LTC.dot(vec_2) % q
	
	flag_vector = np.array([ord(i) for i in FLAG])
	flag_vector = np.reshape(flag_vector, (n,1))
	masked_flag = (flag_vector ^ out_1 ^ out_2) % 256
	masked_flag = np.reshape(masked_flag, (n,))
	masked_flag = ''.join([hex(_)[2:].zfill(2) for _ in masked_flag])
	return masked_flag.encode('utf-8')

def main():
	border = "|"
	pr(border*72)
	pr(border, " Welcome to chaffymask combat, we implemented a masking method to   ", border)
	pr(border, " hide our secret. Masking is done by your 1024 bit input salt. Also ", border)
	pr(border, " I noticed that there is a flaw in my method. Can you abuse it and  ", border)
	pr(border, " get the flag? In each step you should send salt and get the mask.  ", border)
	pr(border*72)

	m, n = 512, 64 
	IVK = [
	3826, 476, 3667, 2233, 1239, 1166, 2119, 2559, 2376, 1208, 2165, 2897, 830, 529, 346, 150, 2188, 4025, 
	3667, 1829, 3987, 952, 3860, 2574, 959, 1394, 1481, 2822, 3794, 2950, 1190, 777, 604, 82, 49, 710, 1765, 
	3752, 2970, 952, 803, 873, 2647, 2643, 1096, 1202, 2236, 1492, 3372, 2106, 1868, 535, 161, 3143, 3370, 
	1, 1643, 2147, 2368, 3961, 1339, 552, 2641, 3222, 2505, 3449, 1540, 2024, 618, 1904, 314, 1306, 3173, 
	4040, 1488, 1339, 2545, 2167, 394, 46, 3169, 897, 4085, 4067, 3461, 3444, 118, 3185, 2267, 3239, 3612, 
	2775, 580, 3579, 3623, 1721, 189, 650, 2755, 1434, 35, 3167, 323, 589, 3410, 652, 2746, 2787, 3665, 828, 
	3200, 1450, 3147, 720, 3741, 1055, 505, 2929, 1423, 3629, 3, 1269, 4066, 125, 2432, 3306, 4015, 2350, 
	2154, 2623, 1304, 493, 763, 1765, 2608, 695, 30, 2462, 294, 3656, 3231, 3647, 3776, 3457, 2285, 2992, 
	3997, 603, 2342, 2283, 3029, 3299, 1690, 3281, 3568, 1927, 2909, 1797, 1675, 3245, 2604, 1272, 1146, 
	3301, 13, 3712, 2691, 1097, 1396, 3694, 3866, 2066, 1946, 3476, 1182, 3409, 3510, 2920, 2743, 1126, 2154, 
	3447, 1442, 2021, 1748, 1075, 1439, 3932, 3438, 781, 1478, 1708, 461, 50, 1881, 1353, 2959, 1225, 1923, 
	1414, 4046, 3416, 2845, 1498, 4036, 3899, 3878, 766, 3975, 1355, 2602, 3588, 3508, 3660, 3237, 3018, 
	1619, 2797, 1823, 1185, 3225, 1270, 87, 979, 124, 1239, 1763, 2672, 3951, 984, 869, 3897, 327, 912, 1826, 
	3354, 1485, 2942, 746, 833, 3968, 1437, 3590, 2151, 1523, 98, 164, 3119, 1161, 3804, 1850, 3027, 1715, 
	3847, 2407, 2549, 467, 2029, 2808, 1782, 1134, 1953, 47, 1406, 3828, 1277, 2864, 2392, 3458, 2877, 1851, 
	1033, 798, 2187, 54, 2800, 890, 3759, 4085, 3801, 3128, 3788, 2926, 1983, 55, 2173, 2579, 904, 1019, 
	2108, 3054, 284, 2428, 2371, 2045, 907, 1379, 2367, 351, 3678, 1087, 2821, 152, 1783, 1993, 3183, 1317, 
	2726, 2609, 1255, 144, 2415, 2498, 721, 668, 355, 94, 1997, 2609, 1945, 3011, 2405, 713, 2811, 4076, 
	2367, 3218, 1353, 3957, 2056, 881, 3420, 1994, 1329, 892, 1577, 688, 134, 371, 774, 3855, 1461, 1536, 
	1824, 1164, 1675, 46, 1267, 3652, 67, 3816, 3169, 2116, 3930, 2979, 3166, 3944, 2252, 2988, 34, 873, 
	1643, 1159, 2822, 1235, 2604, 888, 2036, 3053, 971, 1585, 2439, 2599, 1447, 1773, 984, 261, 3233, 2861, 
	618, 465, 3016, 3081, 1230, 1027, 3177, 459, 3041, 513, 1505, 3410, 3167, 177, 958, 2118, 326, 31, 2663, 
	2026, 2549, 3026, 2364, 1540, 3236, 2644, 4050, 735, 280, 798, 169, 3808, 2384, 3497, 1759, 2415, 3444, 
	1562, 3472, 1151, 1984, 2454, 3167, 1538, 941, 1561, 3071, 845, 2824, 58, 1467, 3807, 2191, 1858, 106, 
	3847, 1326, 3868, 2787, 1624, 795, 3214, 1932, 3496, 457, 2595, 3043, 772, 2436, 2160, 3428, 2005, 2597, 
	1932, 101, 3528, 1698, 3663, 900, 3298, 1872, 1179, 3987, 3695, 3561, 1762, 3785, 3005, 2574, 6, 1524, 
	2738, 1753, 2350, 558, 800, 3782, 722, 886, 2176, 3050, 221, 1925, 564, 1271, 2535, 3113, 1310, 2098, 
	3011, 964, 3281, 6, 1326, 741, 189, 2632, 373, 1176, 548, 64, 1445, 2376, 1524, 2690, 1316, 2304, 1336, 
	2257, 3227, 2542, 3911, 3460
	]

	LTC = np.zeros([n, m], dtype=(int))
	LTC[0,:] = IVK

	for i in range(1, n):
		for j in range(m // n + 1):
			LTC[i,j*n:(j+1)*n] = np.roll(IVK[j*n:(j+1)*n], i)

	for _ in range(5):
		pr(border, "Give me your salt: ")
		SALT = sc()[:-1]
		SALT = pad(SALT, m // 4)
		MASKED_FLAG = chaffy_mask(SALT, LTC, m, n)
		pr(border, f'masked_flag = {MASKED_FLAG}')

if __name__ == '__main__':
	main()
```

{: file="chaffymasking.py" }



### solve

気にすべきなのは、ランダムが入る部分の以下の二か所

```python
def pad(inp, length):
	result = inp + os.urandom(length - len(inp))
	return result
	
# line 33
xor_salts = int.from_bytes(byte_xor(half1_salt, half2_salt), "big")
if xor_salts == 0:
    half1_salt = byte_xor(half1_salt, os.urandom(m))
```

pad関数は$length = len(inp)$でランダム性が消去でき、xor_saltsは $half1\_salt \neq half2\_salt$にすればいい。

あとはMITHみたく上から$out\_1 ,out\_2$が、下から$masked \_ flag$が求まるので順に逆算して以下のxorで答えを出せばいい

```python
masked_flag = (flag_vector ^ out_1 ^ out_2) % 256
```



ただ、なんで5回もリクエストを受付してるのか...

```python
import numpy as np
import binascii
import os, sys
from pwn import *


io = remote("65.21.255.31" ,31377)
# io = process(["python3",'chaffymasking.py'])
io.recvuntil(b"| Gi")

def send(slt):
    io.recvline()
    io.sendline(slt)
    # print(io.recvline())
    # io.interactive()
    masked_flag = eval(io.recvline(None).decode()[16:])
    return masked_flag

m, n = 512, 64 
IVK = [
	3826, 476, 3667, 2233, 1239, 1166, 2119, 2559, 2376, 1208, 2165, 2897, 830, 529, 346, 150, 2188, 4025, 
	3667, 1829, 3987, 952, 3860, 2574, 959, 1394, 1481, 2822, 3794, 2950, 1190, 777, 604, 82, 49, 710, 1765, 
	3752, 2970, 952, 803, 873, 2647, 2643, 1096, 1202, 2236, 1492, 3372, 2106, 1868, 535, 161, 3143, 3370, 
	1, 1643, 2147, 2368, 3961, 1339, 552, 2641, 3222, 2505, 3449, 1540, 2024, 618, 1904, 314, 1306, 3173, 
	4040, 1488, 1339, 2545, 2167, 394, 46, 3169, 897, 4085, 4067, 3461, 3444, 118, 3185, 2267, 3239, 3612, 
	2775, 580, 3579, 3623, 1721, 189, 650, 2755, 1434, 35, 3167, 323, 589, 3410, 652, 2746, 2787, 3665, 828, 
	3200, 1450, 3147, 720, 3741, 1055, 505, 2929, 1423, 3629, 3, 1269, 4066, 125, 2432, 3306, 4015, 2350, 
	2154, 2623, 1304, 493, 763, 1765, 2608, 695, 30, 2462, 294, 3656, 3231, 3647, 3776, 3457, 2285, 2992, 
	3997, 603, 2342, 2283, 3029, 3299, 1690, 3281, 3568, 1927, 2909, 1797, 1675, 3245, 2604, 1272, 1146, 
	3301, 13, 3712, 2691, 1097, 1396, 3694, 3866, 2066, 1946, 3476, 1182, 3409, 3510, 2920, 2743, 1126, 2154, 
	3447, 1442, 2021, 1748, 1075, 1439, 3932, 3438, 781, 1478, 1708, 461, 50, 1881, 1353, 2959, 1225, 1923, 
	1414, 4046, 3416, 2845, 1498, 4036, 3899, 3878, 766, 3975, 1355, 2602, 3588, 3508, 3660, 3237, 3018, 
	1619, 2797, 1823, 1185, 3225, 1270, 87, 979, 124, 1239, 1763, 2672, 3951, 984, 869, 3897, 327, 912, 1826, 
	3354, 1485, 2942, 746, 833, 3968, 1437, 3590, 2151, 1523, 98, 164, 3119, 1161, 3804, 1850, 3027, 1715, 
	3847, 2407, 2549, 467, 2029, 2808, 1782, 1134, 1953, 47, 1406, 3828, 1277, 2864, 2392, 3458, 2877, 1851, 
	1033, 798, 2187, 54, 2800, 890, 3759, 4085, 3801, 3128, 3788, 2926, 1983, 55, 2173, 2579, 904, 1019, 
	2108, 3054, 284, 2428, 2371, 2045, 907, 1379, 2367, 351, 3678, 1087, 2821, 152, 1783, 1993, 3183, 1317, 
	2726, 2609, 1255, 144, 2415, 2498, 721, 668, 355, 94, 1997, 2609, 1945, 3011, 2405, 713, 2811, 4076, 
	2367, 3218, 1353, 3957, 2056, 881, 3420, 1994, 1329, 892, 1577, 688, 134, 371, 774, 3855, 1461, 1536, 
	1824, 1164, 1675, 46, 1267, 3652, 67, 3816, 3169, 2116, 3930, 2979, 3166, 3944, 2252, 2988, 34, 873, 
	1643, 1159, 2822, 1235, 2604, 888, 2036, 3053, 971, 1585, 2439, 2599, 1447, 1773, 984, 261, 3233, 2861, 
	618, 465, 3016, 3081, 1230, 1027, 3177, 459, 3041, 513, 1505, 3410, 3167, 177, 958, 2118, 326, 31, 2663, 
	2026, 2549, 3026, 2364, 1540, 3236, 2644, 4050, 735, 280, 798, 169, 3808, 2384, 3497, 1759, 2415, 3444, 
	1562, 3472, 1151, 1984, 2454, 3167, 1538, 941, 1561, 3071, 845, 2824, 58, 1467, 3807, 2191, 1858, 106, 
	3847, 1326, 3868, 2787, 1624, 795, 3214, 1932, 3496, 457, 2595, 3043, 772, 2436, 2160, 3428, 2005, 2597, 
	1932, 101, 3528, 1698, 3663, 900, 3298, 1872, 1179, 3987, 3695, 3561, 1762, 3785, 3005, 2574, 6, 1524, 
	2738, 1753, 2350, 558, 800, 3782, 722, 886, 2176, 3050, 221, 1925, 564, 1271, 2535, 3113, 1310, 2098, 
	3011, 964, 3281, 6, 1326, 741, 189, 2632, 373, 1176, 548, 64, 1445, 2376, 1524, 2690, 1316, 2304, 1336, 
	2257, 3227, 2542, 3911, 3460
	]

LTC = np.zeros([n, m], dtype=(int))
LTC[0,:] = IVK
for i in range(1, n):
	for j in range(m // n + 1):
		LTC[i,j*n:(j+1)*n] = np.roll(IVK[j*n:(j+1)*n], i)

def byte_xor(a, b):
	return bytes(_a ^ _b for _a,_b in zip(a,b)) 

def pad(inp, length):
	assert len(inp) == length
	result = inp + os.urandom(length - len(inp))
	return result


def make_chaffy_mask(salt, LTC, m, n):
	q = n ** 2
	half1_salt = salt[:m // 8]
	half2_salt = salt[m // 8:]
	xor_salts = int.from_bytes(byte_xor(half1_salt, half2_salt), "big")
	if xor_salts == 0:
		return None,None
		# half1_salt = byte_xor(half1_salt, os.urandom(m))
	half1_binStr = "{:08b}".format(int(half1_salt.hex(),16))
	if(len(half1_binStr) < m):
		half1_binStr = "0" * (m - len(half1_binStr)%m) + half1_binStr
	half2_binStr = "{:08b}".format(int(half2_salt.hex(),16))
	if(len(half2_binStr) < m):
		half2_binStr = "0" * (m - len(half2_binStr)%m) + half2_binStr
	
	vec_1 = np.array(list(half1_binStr), dtype=int)
	vec_1 = np.reshape(vec_1, (m,1))
	vec_2 = np.array(list(half2_binStr), dtype=int)
	vec_2 = np.reshape(vec_2, (m,1))
	
	out_1 = LTC.dot(vec_1) % q
	out_2 = LTC.dot(vec_2) % q
	return out_1, out_2

def mith(mask_enc,out1,out2):
	enc = []
	for i in range(0,len(mask_enc)//2):
		print(i,mask_enc[2*i:2*(i+1)])	
		tmp = int(mask_enc[2*i:2*(i+1)],16)
		enc.append(tmp)
	enc_vector = np.array(enc)
	enc_vector = np.reshape(enc_vector, (n,1))
	ans_vec = (enc_vector^out1^out2)%256
	ans_vec =  np.reshape(ans_vec, (n))
	ans = [chr(i) for i in ans_vec]
	print("".join(ans))

SALT = os.urandom(m // 4)

salt = pad(SALT, m // 4)
out1,out2 = make_chaffy_mask(salt, LTC, m, n)
enc = send(SALT)
mith(enc.decode(),out1,out2)

# ASIS{Lattice_based_hash_collision_it_was_sooooooooooooooo_easY!}



```

{: file="solve.py" }

## [crypto] Mariana [56 solve]

### chall

```python
#!/usr/bin/env python3

from Crypto.Util.number import *
import sys
# from flag import flag

def die(*args):
	pr(*args)
	quit()

def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()

def sc():
	return sys.stdin.buffer.readline()

def main():
	border = "|"
	pr(border*72)
	pr(border, "Welcome to MARIANA cryptography battle, the mission is solving super", border)
	pr(border, "hard special DLP problem in real world, are you ready to fight?     ", border)
	pr(border*72)

	NBIT = 32
	STEP = 40

	pr(border, "In each step solve the given equation and send the solution for x.  ", border)
	c = 1
	while c <= STEP:
		nbit = NBIT * c
		p = getPrime(nbit)
		g = getRandomRange(3, p)
		pr(border, f'p = {p}')
		pr(border, f'g = {g}')
		pr(border, 'Send the solution x = ')
		ans = sc()
		try:
			x = int(ans)
		except:
			die(border, 'Given number is not integer!')
		if x >= p:
			die(border, "Kidding me!? Your solution must be smaller than p :P")
		if (pow(g, x, p) - x) % p == 0:
			if c == STEP:
				die(border, f"Congratz! the flag is: {flag}")
			else:
				pr(border, "Good job, try to solve the next level!")
				c += 1
		else:
			die(border, "Try harder and smarter to find the solution!")

if __name__ == '__main__':
	main()
```

{: file="Mariana.py" }

### solve

なにも考えずに、条件で$x < p$ が通ることが確認できるので、 $p-1$投げておしまいです。

```python
from pwn import *


io = remote("65.21.255.31" ,32066)
io.recvuntil(b"x.   |")
print(io.recvline())

ps = []
gs = []
anss = 1

cnt = 1
while cnt < 40:
    # recv
    p = int(io.recvline(None).decode()[5:])
    g = int(io.recvline(None).decode()[5:])
    ps.append(p)
    gs.append(g)
    io.recvline()
    
    # calc
    ans = 1-p
    io.sendline(str(ans).encode())
    result =  io.recvline()
    print("[+] result... ",result)
    if b"ASIS" in result:
        exit()

# ASIS{fiX3d_pOIn7s_f0r_d!5Cret3_l0g4riThmS!}

```

{: file="solve.py" }

## [crypto] Mindseat [33 solve]

### chall

```python
#!/usr/bin/env python3

from Crypto.Util.number import *
from secret import params, flag

def keygen(nbit, k): # Pubkey function
	_p = 1
	while True:
		p, q = [_p + (getRandomNBitInteger(nbit - k) << k) for _ in '01']
		if isPrime(p) and isPrime(q):
			while True:
				s = getRandomRange(2, p * q)
				if pow(s, (p - 1) // 2, p) * pow(s, (q - 1) // 2, q) == (p - 1) * (q - 1):
					pubkey = p * q, s
					return pubkey

def encrypt(pubkey, m):
	n, s = pubkey
	r = getRandomRange(2, n)
	return pow(s, m, n) * pow(r, 2 ** k, n) % n

flag = flag.lstrip(b'ASIS{').rstrip(b'}')
nbit, k = params
PUBKEYS = [keygen(nbit, k) for _ in range(4)]
flag = [bytes_to_long(flag[i*8:i*8 + 8]) for i in range(4)]
ENCS = [encrypt(PUBKEYS[_], flag[_]) for _ in range(4)]

print(f'PUBKEYS = {PUBKEYS}')
print(f'ENCS = {ENCS}')
```

{: file="mindseat_updated.py" }

### solve

今回の時間食った元凶君(まじで)

さておき、この問題は2 パートに分かれます

- $n$から$p,q$の復元
- $enc = s^m * r^{2 ^ k} \pmod n$ から $m$ の復元



#### part 1

手始めにgetRandomNBitIntegerの $k$ の値を知る必要があるが、単純に$p*q = (r_p*2^k+1)*(r_q*2^k+1)$ を考えれば、$ n$ の下位ビットを見て$0$ が続く長さを考えれば $k$ の値を決め打ちできる。今回は $134$ だった。

それにより $r_p,r_q$ の長さも見えてくる。$n$ が$512$ビットより$p,q$ のそれぞれの乱数部分の長さは $256-k$ ビットとなり。defundパイセンの[coppersmith]([defund/coppersmith: Coppersmith's method for multivariate polynomials (github.com)](https://github.com/defund/coppersmith))で復元できる。

```python
def dec_para(PUB,ENC):
    N,s = PUB
    
    k = 134
    P.<x, y> = PolynomialRing(Zmod(N))
    _p = 1
    poly3 = (x*2^k + _p)*(y*2^k + _p)

    bounds = (2^(256-k), 2^(256-k))
    roots = small_roots(poly3, bounds, m=2, d=2)[0]
    print(roots)
    p = roots[0]*2^k + _p
    q = roots[1]*2^k + _p
    assert isPrime(int(p))
    assert isPrime(int(q))
    assert p*q==N
```

{: file="dec_para.py" }



#### part 2

$enc = s^m * r^{2 ^ k} \pmod n$ より $r$ が邪魔なので$enc^{\frac{\phi(n)}{2^k}} = s^{\frac{m\phi(n)}{2^k}} * r^{\phi(n)} \pmod n = s^{\frac{m\phi(n)}{2^k}} \pmod n$ になり、dis_cretelogで求めてしまい

```python
def decrypt(p,q,s,c):
    n = p*q
    k  =134
    phi = (p-1)*(q-1)
    e = pow(2,k)
    e_ = int(p-1)//int(e)
    m = discrete_log(GF(p)(c)^e_,GF(p)(s)^e_, operation="*")
    print(long_to_bytes(m))
    return long_to_bytes(m)
```

{: file="decrypt.py" }

```python
from Crypto.Util.number import *
import itertools
PUBKEYS = [(10342840547250370454282840290754052390564265157174829726645242904324433774727630591803186632486959590968595230902808369991240437077297674551123187830095873, 5179654005441544601140101875149402241567866059199512232495766031194848985776186595289740052214499657697650832860279375151687044465018028876445070588827777), (6015512135462554031390611730578383462516861987731833360559070749140159284050335604168414434218196369921956160353365713819898567416920672209509202941444097, 2116441415129068001049624780654272734931672052541246678702416144768611225693039503554945326959705314527114860312641379671935648337975482830939466425225421), (6396980904648302374999086102690071222661654639262566535518341836426544747072554109709902085144158785649143907600058913175220229111171441332366557866622977, 1760317994074087854211747561546045780795134924237097786412713825282874589650448491771874326890983429137451463523250670379970999252639812107914977960011738), (9158217300815233129401608406766983222991414185115152402477702381950519098200234724856258589693986849049556254969769863821366592458050807400542885348638721, 6564146847894132872802575925374338252984765675686108816080170162797938388434600448954826704720292576935713424103133182090390089661059813982670332877677256)]
ENCS = [4595268033054096192076432659360373235610019564489694608733743330870893803828258295069937060360520598446948290913045781945314108935153236291467160667601985, 3390637292181370684803039833768819598968576813582112632809296088618666221278429695211004046274005776653775480723833818255766663573061866194380012311184611, 5197599582013327040903216369733466147938613487439777125659892779696104407398257678982801768761973934713675657188014051286238194316997970299887749668838196, 5093835186720390391696398671365109925058893544530286148616117890366909889206952477053316867658405460457795493886317792695055944930027477761411273933822112]

def small_roots(f, bounds, m=1, d=None):
	if not d:
		d = f.degree()

	R = f.base_ring()
	N = R.cardinality()
	
	f /= f.coefficients().pop(0)
	f = f.change_ring(ZZ)

	G = Sequence([], f.parent())
	for i in range(m+1):
		base = N^(m-i) * f^i
		for shifts in itertools.product(range(d), repeat=f.nvariables()):
			g = base * prod(map(power, f.variables(), shifts))
			G.append(g)

	B, monomials = G.coefficient_matrix()
	monomials = vector(monomials)

	factors = [monomial(*bounds) for monomial in monomials]
	for i, factor in enumerate(factors):
		B.rescale_col(i, factor)

	B = B.dense_matrix().LLL()

	B = B.change_ring(QQ)
	for i, factor in enumerate(factors):
		B.rescale_col(i, 1/factor)

	H = Sequence([], f.parent().change_ring(QQ))
	for h in filter(None, B*monomials):
		H.append(h)
		I = H.ideal()
		if I.dimension() == -1:
			H.pop()
		elif I.dimension() == 0:
			roots = []
			for root in I.variety(ring=ZZ):
				root = tuple(R(root[var]) for var in f.variables())
				roots.append(root)
			return roots

	return []

def decrypt(p,q,s,c):
    n = p*q
    k  =134
    phi = (p-1)*(q-1)
    e = pow(2,k)
    e_ = int(p-1)//int(e)
    m = discrete_log(GF(p)(c)^e_,GF(p)(s)^e_, operation="*")
    print(long_to_bytes(m))
    return long_to_bytes(m)

def dec_para(PUB,ENC):
    N,s = PUB
    
    k = 134
    P.<x, y> = PolynomialRing(Zmod(N))
    _p = 1
    poly3 = (x*2^k + _p)*(y*2^k + _p)

    bounds = (2^(256-k), 2^(256-k))
    roots = small_roots(poly3, bounds, m=2, d=2)[0]
    print(roots)
    p = roots[0]*2^k + _p
    q = roots[1]*2^k + _p
    assert isPrime(int(p))
    assert isPrime(int(q))
    assert p*q==N
    return decrypt(int(p),int(q),int(s),int(ENC))
    

flag = b""
for i in range(4):
    flag +=dec_para(PUBKEYS[i],ENCS[i])
    
print(b"ASIS{"+flag+b"}")
# ASIS{N3w_CTF_nEW_Joye_Libert_CrYpt0_5}
```

{: file="solve.py" }



## [crypto] Desired curve　[16 solve]



### chall



```python
#!/usr/bin/env sage

import sys
from Crypto.Util.number import *
from flag import flag

def die(*args):
	pr(*args)
	quit()

def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()

def sc():
	return sys.stdin.buffer.readline()

def main():
	border = "|"
	pr(border*72)
	pr(border, "Hi all, now it's time to solve a relatively simple challenge about  ", border)
	pr(border, "relatively elliptic curves! We will generate an elliptic curve with ", border)
	pr(border, "your desired parameters, are you ready!?                            ", border)
	pr(border*72)

	nbit = 256
	q = getPrime(nbit)
	F = GF(q)

	while True:
		pr(border, "Send the `y' element of two points in your desired elliptic curve:  ")
		ans = sc()
		try:
			y1, y2 = [int(_) % q for _ in ans.split(b',')]
		except:
			die(border, "Your parameters are not valid! Bye!!")
		A = (y1**2 - y2**2 - 1337**3 + 31337**3) * inverse(-30000, q) % q
		B = (y1**2 - 1337**3 - A * 1337) % q
		E = EllipticCurve(GF(q), [A, B])
		G = E.random_point()

		m = bytes_to_long(flag)
		assert m < q
		C = m * G
		pr(border, f'The parameters and encrypted flag are:')
		pr(border, f'q = {q}')
		pr(border, f'G = ({G.xy()[0]}, {G.xy()[1]})')
		pr(border, f'm * G = ({C.xy()[0]}, {C.xy()[1]})')

		pr(border, f'Now find the flag :P')

if __name__ == '__main__':
	main()
```

{: file="desiredcurve.py" }



### solve

やることは簡単で、

- invalid curve attack でsubgroupのオーダーが小さいものを見つける。
- それを、集めてCRTで復元する。

```python
from pwn import *
from timeout_decorator import timeout
from random import randint
from Crypto.Util.number import *

io = remote("65.21.255.31" ,10101)
io.recvuntil(b"| Se")


def send(y1,y2):
    io.recvline()
    io.sendline((str(y1)+","+str(y2)).encode())
    io.recvline()
    q = int(io.recvline(None).decode()[5:])
    G = io.recvline(None).decode()[2+4+1:].split(",")
    mG = io.recvline(None).decode()[2+8+1:].split(",")
    Gx = int(G[0])
    Gy = int(G[1].replace(")",""))
    mGx = int(mG[0])
    mGy = int(mG[1].replace(")",""))    
    io.recvline()
    return q , (Gx,Gy) ,(mGx,mGy)


# I adjusted to https://furutsuki.hatenablog.com/entry/2020/05/05/112207
def search_para(P):
    @timeout(10, timeout_exception=Exception, use_signals=False)
    def factorize(n):
        return prime_factors(n)

    F = GF(P)
    while True:
    
        y1 = randint(2,P-1)
        y2 = randint(2,P-1)
        A = (y1**2 - y2**2 - 1337**3 + 31337**3) * pow(-30000,-1, q) % q
        B = (y1**2 - 1337**3 - A * 1337) % q
        EC = EllipticCurve(F, [A, B])
        order = EC.order()

        try:
            factors = factorize(order)
        except Exception:
            continue

        suborder = 1
        for f in factors:
            if f < 10**10:
                suborder = f
            else:
                break
        g = EC.gen(0) * int(order // suborder)
        
        # print({
        #     "generator": g.xy(),
        #     "order": suborder,
        #     "y1": y1,
        #     "y2":y2,
        #     "q": q,
        # }, ",")
        
        return y1,y2,suborder

y1,y2 = 1,1

q, G, mG= send(y1,y2)
A = (y1**2 - y2**2 - 1337**3 + 31337**3) * pow(-30000,-1, q) % q
B = (y1**2 - 1337**3 - A * 1337) % q
E = EllipticCurve(GF(q),[A,B])

dlog = []
odr = []
phimation = 1
while True:
    y1,y2,suborder = search_para(q)
    q, G, mG= send(y1,y2)
    A = (y1**2 - y2**2 - 1337**3 + 31337**3) * pow(-30000,-1, q) % q
    B = (y1**2 - 1337**3 - A * 1337) % q
    E = EllipticCurve(GF(q),[A,B])
    G = E(G)
    mG = E(mG)
    phimation *= suborder
    print("[*] subord =", suborder)    
    print("[*] persentage =", (100*int(phimation).bit_length())//int(E.order()).bit_length(),"%")
    
    print("[*] start dlog")
    dlog.append(discrete_log(mG*(E.order()//suborder),G*(E.order()//suborder), operation="+",ord=E.order()))
    odr.append(suborder)
    
    m = long_to_bytes(int(CRT(dlog, odr)))
    print("[+] find dlog ...",m, end = "\n\n")
    if b"ASIS" in m:
        exit()
# ASIS{(e$l6LH_JfsJ:~<}1v&}
```

{: file="solve.py" }

