# Official Writeups of Crypto Chals in Mini L CTF 2024

> Curvesigin Revenge
>
> Ezfactor
>
> Modular
>
> MinTrix
>
> Sums
>

Author: Orac1e@XDSEC&L-team
date: 2024.05.09

>tl;dr

## Curvesignin Revenge

"The Revenge of the curvesignin!"

简单分析下题目源码：

```python
from random import randint
from os import urandom
from collections import namedtuple
from hashlib import sha256

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import pad
from secret import FLAG


Point = namedtuple("Point", "x y")


def add(P, Q):
    Px, Py = P.x, P.y
    Qx, Qy = Q.x, Q.y
    Rx = (Px*Qx-e*Py*Qy) % N
    Ry = (Px*Qy+Py*Qx) % N
    return Point(Rx ,Ry)


def mul(P, exp):
    Q = Point(1, 0)
    while exp > 0:
        if exp & 1:
            Q = add(Q, P)
        P = add(P, P)
        exp >>= 1
    return Q


def gen_key():
    private_key = randint(1, N)
    public_key = mul(G, private_key)
    return (public_key, private_key)


def share_secret(P, d):
    return mul(P, d).x


def encrypt(share_secret, flag):
    key = sha256(long_to_bytes(share_secret)).digest()[:16]
    iv = urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(flag,16))
    data = {"iv":iv.hex(),"encrypt_flag":ciphertext.hex()}
    return data


N = 61820395509869592945047899644070363303060865412602815892951881829112472104091
e = 133422
G = Point(37234080987968345210046814543941568534026683208134935256498818666416936228347,23681207802011885401101067347527183297441941230486570817545706194562153385116)
Alice_pub, n_a = gen_key()
Bob_pub, n_b = gen_key()
assert (Alice_pub.x**2 + e*Alice_pub.y**2) % N == 1
assert (Bob_pub.x**2 + e*Bob_pub.y**2) % N == 1

print(f"Alice's public key: {Alice_pub}")
print(f"Bob's public key: {Bob_pub}")

share = share_secret(Bob_pub, n_a)
enc = encrypt(share, FLAG)

print(f'Encrypted flag: {enc}')
```

定义了一个圆锥曲线$E:x^2+e\cdot y^2=1(\bmod N)$。针对其上所有的点所构成的加法群，笔者定义了一个简单的Diffie-Hellman key exchange。为了获得`share_secret`，我们需要去求解这个圆锥曲线上的离散对数问题。

注意到$N$为素数，且$e$是模$N$的二次剩余，那么我们设$d$满足$d^2\equiv e\bmod N$

曲线$E$上的任意一点$G(x_0,y_0)$，都满足如下方程：

$$x_0^2+e\cdot y_0^2\equiv 1\bmod N$$

代数变形一下，得到：

$$(x_0+i\cdot d\cdot y_0)\cdot (x_0-i\cdot d\cdot y_0)\equiv 1\bmod N,i^2+1=0$$

可以看到曲线$E$上的点与模$N$的高斯整数$x_0+i\cdot d\cdot y_0$是相互对应的。

不难验证如上的对应关系其实是一个同态。那么我们可以将曲线$E$上的离散对数问题转换到有限域$\mathbb{F}_{N^2}$上去。
（注意到$N$为一高斯素数）

对于$s = x_0+i\cdot d\cdot y_0$，注意到有：

$$s^{N+1}=x_0^{N+1}+\sum_{k=1}^{N-1}x_{0}^{k}{N\choose k}(i\cdot d\cdot y_0)^{N-k} + (i\cdot d\cdot y_0)^{N+1}\equiv x_0^2+e\cdot y_0^2\equiv 1\bmod N$$

所以$s$的阶为$N+1$，尝试将$N+1$进行分解，发现其十分光滑：

```python
sage: factor(N+1)
2^2 * 7 * 877 * 2269 * 37967 * 184279 * 504877 * 845833 * 12308089 * 25153483 * 135503999 * 149848639 * 223321729 * 264522527
```

那么我们可以尝试用Pohlig-Hellman算法来求解这个离散对数问题。

### solution

留给读者作为练习题

## Ezfactor

题目源码如下：

```python
from sage.all import *
from Crypto.Util.number import *
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from sercret import p,q,x1,y1,x2,y2,flag


e = 107851261855564315073903829182423950546788346138259394246439657948476619948171
n = 1612520630363003059353142253089981533043311564255746310310940263864745479492015266264329953981958844235674179099410756219312942121244956701500870363219075525408783798007163550423573845701695879459236385567459569561236623909034945892869546441146006017614916909993115637827270568507869830024659905586004136946481048074461682125996261736024637375095977789425181258537482384460658359276300923155102288360474915802803118320144780824862629986882661190674127696656788827

assert x1**2 + e*y1**2 == n
assert x2**2 + e*y2**2 == n
assert x1 != x2 and y1 != y2
assert p.bit_length() == q.bit_length() == 768


key = long_to_bytes(x1+x2+y1+y2)[:16]
iv = long_to_bytes((x1^x2)+(y1^y2))[:16]
cipher = AES.new(key,AES.MODE_CBC,iv)
Flag = cipher.encrypt(pad(flag,16)).hex()
gift = p>>360
print(Flag)
print(gift)
print(e)


'''
725039090b61b83a729d1e1061de62f0aae6b3c13aa601e2302b88393a910086497ccb4ef1e8d588a0fffe1e7b2ac46e
484571358830397929370234740984952703033447536470079158146615136255872598113610957918395761289775053764210538009624146851126
107851261855564315073903829182423950546788346138259394246439657948476619948171
'''
```

简单分析一下：$N=p\cdot q$，其中$p,q$是大小为$768$bits的素数。且$N$满足如下条件：

$$
\begin{align*}
x_1^2+e\cdot y_1^2&=N\\
x_2^2+e\cdot y_2^2&=N\\
x_1\neq x_2,y_1&\neq y_2\\
\end{align*}
$$

此外，笔者还提供了素数$p$的一部分信息：`p>>360`。

### Idea

笔者尝试从出题人的视角来简单解释下本题的一些idea:

初看此题，可能会感觉无从下手。在看到`p>>360`后，选手可能会使用Coppersmith method将模数$N$进行分解。但是当我们得到了$N=p\cdot q$的分解后，该如何进一步求解下面的丢番图方程:

$$x^2+e\cdot y^2=N$$

到了这里，大部分选手一般会去尝试Google这个方程的求解方法，然后可以找到一些`useful`的算法。但是，笔者这里还是想提醒大家注意题目的描述："Just an easy number theory problem."。我们还是可以尝试运用所学的数论知识去推一推这个方程的求解方法，而不必借助Mathematicians的智慧。

首先，笔者想先引入一个经典著名的数论中的定理：

> Fermat's two square theorem

形如$4\cdot k + 1$的素数$p$可以被分解为如下的二平方和：

$$x^2+y^2=p\quad x,y\in\mathbb{N}$$

其证明方法有很多，这里笔者给出一种较为`interseting`的证明方法。

$\textbf{Proof}$

首先注意到$-1$为模$p$的二次剩余，这里我们设$e$满足：$e^2\equiv-1\bmod p$。

然后我们构造格$\mathcal{L}$，其格基矩阵如下：

$$\\
\\
M = \begin{bmatrix}
1 & e\\
0 & p\\
\end{bmatrix}
$$

对于其中的向量$\vec{t}=\vec{v}\cdot M=(x_0,y_0)\cdot M=(x_1,y_1)$

我们有$x_1=x_0,y_1=e\cdot x_0+p\cdot y_0$，考虑其范数，有
$$\Vert \vec{t}\Vert=x_0^2+(e\cdot x_0+p\cdot y_0)^2=(e^2+1)\cdot x_0^2 + p^2\cdot y_0^2 + 2\cdot e\cdot p\cdot x_0\cdot y_0$$

两边模$p$，得到$\Vert \vec{t} \Vert \equiv 0 \bmod p$，也就是说对于格$\mathcal{L}$中的任意一个向量$\vec{t}$，我们均有$\Vert \vec{t}\Vert=k\cdot p$。

考虑格$\mathcal{L}$中的最短非零向量，我们尝试估计其长度。

因为有$\det(M)=p$，所以格$\mathcal{L}$中的最短非零向量长度满足
$0<\Vert \vec{t_0} \Vert^2 < 2\cdot p$。

综上我们有$\Vert \vec{t_0} \Vert^2 = x_0^2 + y_0^2 = p$。证明完毕。

注：上面的证明过程其实提供了一种求解方程$x^2+y^2=p$的有效算法：在格$\mathcal{L}$中利用格基规约算法去寻找短向量。

有了上面的`theorem`和`proof`，对于本题中的丢番图方程$x^2+e\cdot y^2 = N$，我们可以尝试几乎完全相同的方法去求解。具体细节留给读者作为习题。

### detail

> 关于使用Coppersmith method在已知`p>>360`的情况下，分解整数$N$的一些细节问题。

在比赛过程中，部分选手向我反馈：Coppersmith method的调参过程非常的折磨，甚至有些玄学。于是我觉得有必要在writeup里面详细解析下。

首先我们先来回顾下`Coppersmith theorem`：

Let $N$ be an integer of unknown factorization, which has a divisor $b\geq N^{\beta},0<\beta\leq 1$. Let $0<\epsilon\leq \frac{1}{7}\beta$. Furthermore, let $f(x)$ be a univariate monic polynomial of degree $\delta$. Then, we can find all solutions $x_0$ for the equation:

$$f(x)\equiv 0\bmod b \text{ with } \vert x_0\vert \leq \frac{1}{2}N^{\frac{\beta^2}{\delta}-\epsilon}$$

The running time is dominated by the time to LLL-reduce a lattice basis of dimension $O(\epsilon^{-1}\delta)$ with entries of bit-size $O(\epsilon^{-1}\log N)$. This can be achieved in time $O(\epsilon^{-7}\delta^{5}\log^2 N)$

那么，我们设多项式$f(x)$为$2^h \cdot p_h + x$，其具有小根$x_0$，满足：

$$2^{h}\cdot p_h + x_0=p$$

$x_0$的上界$X=2^{360}<N^{1/4}$（这里笔者提供了相当充足的$p$的高位信息）

这里，笔者选择使用sagemath中内置的`small_roots()`函数进行求解。

关于参数的选取问题：

1. $p\geq N^{\beta}$，因为$p\cdot q = N,p\neq q$，$\beta$的取值可以略小于$\frac{1}{2}$，例如$0.49$。
2. 小根$x_0$的上界$X$，这里我们直接选取$X=2^{360}$即可。
3. $\varepsilon$的取值，我们这里可以选取$\epsilon=\frac{\beta^2}{\delta}-\log_{N}(2\cdot X)$。实际上，我们可以略微将$\epsilon$的值提升一点，可以有效降低时间开销。）

笔者所使用的参数为$X=2^{360},\beta=0.49,\epsilon=0.01498519292011843$

注：这组参数显然并非最优参数。

## Modular

本意是想考察一下Modular Inversion Hidden Number Problem的求解，但是由于出题人的疏漏，导致这道题被非预期了TOT

预期解法：

参考这篇综述[Hidden Number Problems](https://www.math.auckland.ac.nz/~sgal018/BarakShaniPhD.pdf)的Chapter7即可。

## MinTrix

一道非常有趣的题目。

题目源码如下：

```python
from secret import flag
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes,getPrime

p = getPrime(32)
K = GF(p)
n,m = 66,99

def keygen():
    sk,pk = [],[]
    for _ in range(4):
        A,B = random_matrix(K, m, n),random_matrix(K, n, m) 
        sk.append((A, B))
        pk.append(A*B)
    return (sk, pk)

def dh(sk, pk):
    shared = []
    for csk, cpk in zip(sk, pk):
        A, B = csk
        shared.append((A.transpose() * cpk * B.transpose()).det())
    return shared

skA, pkA = keygen()
skB, pkB = keygen()

shA = dh(skA, pkB)
shB = dh(skB, pkA)

assert shA == shB

shared = b"".join(long_to_bytes(int(x)) for x in shA)
aes = AES.new(shared, AES.MODE_ECB)
ct = aes.encrypt(flag)

save((pkA, pkB, ct.hex()), "output")
```

### analysis

简单分析一下，发现其中定义了一个Diffie-Hellman密钥交换协议。

我们可以验证下其正确性：对于$(A_{0i},B_{0i})\in Sk_{Alice},A_{1i}\cdot B_{1i}\in Pk_{Bob}$

根据行列式的性质，我们有$s_{Alice}^{i}=\det(A_{0i}^{T}\cdot A_{1i}\cdot B_{1i}\cdot B_{0i}^{T})=\det(A_{1i}^{T}\cdot A_{0i}\cdot B_{0i}\cdot B_{1i}^{T})=s_{Bob}^{i}$

假设，我们有矩阵$C,D$，尝试计算$x=\det(C^{T}\cdot A_{1i}\cdot B_{1i}\cdot D^{T})$,那么将会有下式成立：

$$x=\det(A_{1i}^{T}\cdot (C\cdot D)\cdot B_{1i}^{T})$$

那么只要当$C\cdot D=A_{0i}\cdot B_{0i}$时，我们就可以去计算$s^{i}$。

那么现在的问题便转化为了如何将矩阵$A\cdot B$分解为两个矩阵$C_{m\times n},D_{n\times m}$

事实上，存在一种特殊的分解可以满足我们的需求：

`Rank factorization from reduced row echelon form`

其中的具体细节，读者可以自行查询或推导，笔者此处不再赘述。

## Sums

两解

这道题目的解法较多，这里笔者就不再过多赘述了，留给读者作为练习题。（其实是笔者有点懒了）

`hint`:Note the prime number p.

> Talk is cheap. Show me the code.

下面给出笔者的exp以供参考学习:

```python
from Crypto.Util.number import *
from sage.all import *


a =  []
b =  []
cipher = []


def solver(a):
    A = sum(a)
    n = len(a)
    print(A)
    print(A.bit_length())
    print("A <= ",2**(A.bit_length()))
    
    M = Matrix(ZZ,2*n-1,2*n-1)
    M[0,0] = 1
    for i in range(n-1):
        M[0,n+i] = -2*a[i+1]
        M[n+i,n+i] = 2*a[0]
        M[1+i,1+i] = 1
        M[1+i,n+i] = A
    Q = diagonal_matrix(ZZ,[1]+(n-1)*[2**8]+(n-1)*[2**2048])
    M = M * Q
    v = (M.LLL())/Q
    for i in range(2*n-1):
        print(int(abs(v[i][0])).bit_length())
    for vec in v:
        x0 = vec[0]
        y = vec[1:n]
        zero = vec[n:]
        if list(zero) != (n-1)*[0]: continue
        x0_ub = (2*max(a)+ sum(a)*2**128)//max(a)
        x0s = list(range(x0,x0_ub,a[0])) + list(range(-x0,x0_ub,a[0]))
        for x0i in x0s:
            print("have a try")
            g = gcd(x0i,A)
            if gcd(2*a[0],A) % g != 0: continue
            p = inverse_mod(x0i//g,A//g)*(2*a[0]//g)%(A//g)
            if not is_prime(p): continue
            if p == 2: continue
            e = inverse_mod(2,p)*(-A) % p
            if e == 0: continue
            s_vec = [inverse_mod(e,p)*ai % p for ai in a]
            if sum(s_vec) + 2 != p: continue
            if max(s_vec) >= 2**128: continue
            print("found the private key!")
            message = []
            for ci in cipher:
                mi = int(inverse_mod(e,p)*ci % p)
                message.append(mi % 2)
            message = ''.join(map(str,message))
            m = int(message,2)
            m = int.to_bytes(m,(m.bit_length()+7)//8,'big')
            return m

    return None


if __name__ == '__main__':
    ax = solver(a)
    print(ax)
```
