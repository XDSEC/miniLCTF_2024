# Crypto
鉴于本人ctf经验实在有限，mini可能是我的ctf初赛，所以这篇wp可能会有很多萌新才会发出的言论，各位带佬轻点喷））））

首先复盘一下整个比赛，~~虽然这可能不是wp所需要的~~：
我的做题顺序如下：
$Modular \rightarrow EZfactor \rightarrow Mintrix \rightarrow  Curvesignin \rightarrow Sums（5.8 赛后）$

这个做题顺序其实很大地影响到了我后续的解题。
1. Modular 不多说，全程a得最多的题目。
2. EZfactor ，难点在于调参，后面其实比较简单的数论知识，Diophantine equation的一个特殊形式。关于调参狠狠锤一下自己，做题经验太过匮乏，所以即使知道要调参，但是也因为做题少，只会跟着论文里找到的一些理论上的渐进解走，但是像这种题目其实以实际问题为准才是正确的思路。
3. Mintrix dbt学长的矩阵加密，说实话，要不是矩阵加密他本身存在缺陷，我是会绕很久的路的。
4. 接下来，就出问题了,因为mintrix做得过于顺利，所以我坚信curvesignin没有被推广是因为和矩阵加密一样，本身的加密存在缺陷，于是我花了两天时间研究这个曲线，寻找所谓的“缺陷”，但是事实上，我还没有考虑到一个问题，大家加密选的肯定是最优解，比赛结束后问了问随缘学长，对话大概这样：
    >“这个看起来很完美的加密，为什么没有被推广呢？”\
    “一点也不完美啊，相比椭圆曲线和Fp上的离散对数方案毫无优势”\
    “那什么样的加密是完美的呢？”\
    “安全，效率，功能，综合考虑，简单的加密方案，肯定是同样的安全性下，存储空间和计算量越小越好”

    嗯，采购恍然大悟，所以实际最后解题很简单，是我想复杂了，其实也可以认为是ctf经验不足导致的。
5. sums，关于这个题目，我最早意识到他的解密没给出，但是后来想想，这算是隐藏在题目中的一个小hint。但是没太在意，还是揪着背包格嗯解，哪怕我算出来他背包密度是大于1的，几乎没有解的可能）））

感觉我做题存在很大的一个通病就是，不能很快的找到做题的方向，总是会绕很远的路，把所有南墙撞了个遍才能找到最终解。但是这应该是所有人对所有题目都会经历的，但是我错就错在容易一根筋，并且爱钻牛角尖，我特别喜欢研究题目的加密方式，反复地研究，但是就解题而言，这是会拖慢解题速度的很大的一个问题。

感觉这个还是要靠密码分析的经验来弥补，好了，接下来进入正题吧。

## Curvesignin_Revenge
一眼DH，所以大方向比较清晰，就是寻找私钥。

解题思路：N，e 比较小，简单认为是DLP就行。

（~~废话~~)，很容易观察到这个是个cyclic group，群的阶为N+1, 生成元是G，可以观察到N+1是一个光滑数，所以我们考虑$PH+bsgs+crt$，如果预先对$N+1$进行分解的话，时间复杂度非常小，约等于是：$O(\sqrt {max（p_1,....,p_k})$。

~~~ python
from sage.rings import integer_ring
Z = integer_ring.ZZ
def bsgs_alg(a, b, bounds):

    identity = Point(x = 1 , y = 0)
    lb, ub = bounds
    if lb < 0 or ub < lb:
        raise ValueError("bsgs() requires 0<=lb<=ub")

    ran = 1 + ub - lb   # the length of the interval
    # c = op(inverse(b), multiple(a, lb, operation=operation))
    c = add(mul(b , N), mul(a , lb))

    if ran < 30:    # use simple search for small ranges  
        d = c
        for i0 in range(ran):
            i = lb + i0
            if d == identity:        # identity == b^(-1)*a^i, so return i
                return Z(i)
            d = add(a, d)
        raise ValueError("No solution in bsgs()")

    m = ran.isqrt() + 1  # we need sqrt(ran) rounded up
    table = dict()       # will hold pairs (a^(lb+i),lb+i) for i in range(m)

    d = c
    for i0 in xsrange(m):
        i = lb + i0
        if d == identity:        # identity == b^(-1)*a^i, so return i
            return Z(i)
        table[d] = i
        d = add(d, a)

    c = add(c, mul(d , N))     # this is now a**(-m)
    d = identity
    for i in xsrange(m):
        j = table.get(d)
        if j is not None:  # then d == b*a**(-i*m) == a**j
            return Z(i * m + j)
        d = add(c, d)
    
    raise ValueError("Log of %s to the base %s does not exist in %s." % (b, a, bounds))
   

def discrete_log_new(a, base = G, ord=N + 1):
    try:
        f = factor(ord)
        f = list(f)
        # print(f)
        l = [0] * len(f)
        for i, (pi, ri) in enumerate(f):
            for j in range(ri):
                c = bsgs_alg(mul(base , (ord // pi)),
                            mul((add(a ,  mul(base , l[i]*N))) , (ord // pi**(j + 1))),
                            (0, pi))
                l[i] += c * (pi**j)
        from sage.arith.all import CRT_list
        return CRT_list(l, [pi**ri for pi, ri in f])
    except ValueError:
        raise ValueError("No discrete log of %s found to base %s" % (a, base))
    
bsk = discrete_log_new(Bob , G , N+1)
print(bsk)
~~~

得到Bob的私钥，按照DH协议得到公钥，AES正常解密就是了（脚本小子）。

## EZfactor
一眼P高位泄露，管它怎么解呢，先coppersmith爆了！
嗯？怎么爆不出来？？？啊，这咋办？
wuuuu，论文保命。
嗯？论文咋也不对，不是，我这参数这么完美，你在跟我开玩笑吗？
调参？不是，这真能调吗？
不是，这真能调？
总结：格真是玄学。

这大概总结一下，关于调参的事情，论文可以参考这个[coppersmith](https://www.crypto.ruhr-uni-bochum.de/imperia/md/content/may/paper/lll.pdf)。（虽然coppersmith我翻了太多论文了，在这贴不过来了，但是大家自己去搜一下看看应该差不多）

由论文可知：
$coppersmith$的应用场景如下：

现有一个$e$阶的多项式$f$，那么可以：

- 给定$\beta$，快速求出模某个$n$的因数$b$意义下较小的根，其中 $b\geq n^{\beta}$（$0< \beta \leq 1$）
- 在模$n$意义下，快速求出$n^{\frac{\beta^2}{e}}$以内的根

而应用coppersmith定理求解$p_{unknown}$，前提条件是$p_{unknown}\leq n^{\frac{\beta^2}{e}}$。

这道题目用到的高位攻击显然是应用了第二条性质，此时构造的多项式$f=p_{high}+p_{unknown}$（其实构造方法不止一种，可以自行了解一下，我用的是这个，但是其实都差不多），显然阶数为$e=1$，在高位攻击的情况下$e=1$，转换为是求$n^{\beta^2}$

而$\beta$的定义如下：

>$n$的某个因数$b$使得$b\geq n^{\beta}$，（$0< \beta \leq 1$）

而$n=p\cdot q$，其中$p,q$均为大素数,经过验算可知，​当p,q二进制位数相同时最接近边界值的保守做法是取$0.4$（实际上介于$0.4 - 0.5$之间）；如果p,q二进制位数不同，就按照之前的方法具体问题具体分析

注意到题目中的p和q的bit位一致，那我们先保守取到0.4，其他参数根据论文里的进行初始化设置。

~~~ python
sage.rings.polynomial.polynomial_modn_dense_ntl.small_roots(self, X=None, beta=1.0, epsilon=None, **kwds)
~~~

~~~ python
dd = pol.degree()
beta = 0.4                           # we should have q >= N^beta
epsilon = beta / 7                     # <= beta/7
mm = ceil(beta**2 / (dd * epsilon))    # optimized
tt = floor(dd * mm * ((1/beta) - 1))   # optimized
XX = ceil(pow(n , ((beta**2/dd) - epsilon))) # we should have |diff| < X
~~~

我们在这个基础上调参就好，beta以0.01为步长，epsilon我的建议是，直接从0到$\beta/7$遍历一下，步长取0.01。

~~~ python
from sage.all import*
from Crypto.Util.number import*
n = 1612520630363003059353142253089981533043311564255746310310940263864745479492015266264329953981958844235674179099410756219312942121244956701500870363219075525408783798007163550423573845701695879459236385567459569561236623909034945892869546441146006017614916909993115637827270568507869830024659905586004136946481048074461682125996261736024637375095977789425181258537482384460658359276300923155102288360474915802803118320144780824862629986882661190674127696656788827
ph = 484571358830397929370234740984952703033447536470079158146615136255872598113610957918395761289775053764210538009624146851126
phh = ph*(2**360)
e = 107851261855564315073903829182423950546788346138259394246439657948476619948171
kbits = 360 
PR = PolynomialRing(Zmod(n),names = ('x'));(x,) = PR._first_ngens(1)
f = x + phh
p = f.small_roots(X = 2**360,beta = 0.45,epsilon = 0.02)[0] + phh
print(p)
~~~

小科普到此结束，我们开始上面说的[$Diophantine\_ equation$](https://www.math.leidenuniv.nl/~psh/ANTproc/02buhler.pdf)的求解,大概求解思路可以参考这本书里的41页,证明的话我是看的这篇[论文](https://projecteuclid.org/journalArticle/Download?urlId=10.3792%2Fpjaa.80.40)，比较简单，我们这里直接贴代码：

~~~ python

def find_sol(p, d):
    """
    input - a prime p, an absolute value of discriminant d
    output - a primitive solution (x, y) in integers to the equation
    x^2 + d*y^2 = p, if there exists one, otherwise return None.
    """
    t = find_sqrt(p, -d)
    bound = ZZ(int(sqrt(p)))
    n = p
    while True:
        n, t = t, n % t
        if t < bound: 
            break
    if ZZ(gmpy2.iroot((p - t**2)/d ,2)) in ZZ:
        return t, ZZ(sqrt((p - t**2) / d))
    else:
        return None
x, y = find_sol(N, e)
~~~

现在要做的大概就是解决上面代码里提到的$find\_sqrt$，由上面的分解我们可以得到N分解后的p， q，我们这里利用二次剩余+crt可以求出$find\_sqrt(n, -d)$,即-d关于n的二次剩余，（注意这里是-d，实际上通过验证我们可以知道$p\%4 = 3$, 根据欧拉判法，不存在 d 关于 p的二次剩余，当时在这卡了很久，自锤一下 ），根据小学知识，理论上会有四组解$x,y$的解，验证排除一下就行吧，（~~我可能运气比较好，我最开始试的两组解就是对的~~）。

## mintrix
两种解法，但是写到这我已经累了，所以后面可能能水就水了……

1. 
第一种思路把puk转化成rref形式然后按直接分解吧，因为这的矩阵转化成rref形式之后pivots刚好是前60列，这是必然的，可以自行证明一下。
![1.png](https://img2.imgtp.com/2024/05/09/sqjEcJc3.png)
exp如下：
~~~ python
shA = []
matA, matB, flag = load(r'/root/ctf/mintrix/output.sobj')
for i in range(4):
    m1 = matA[i].rref()
    m2 = matB[i].rref()
    B1.append(m1[:66,:99])
    A1.append(m1[:99,:66])
    B2.append(m2[:66,:99])
    A2.append(m2[:99,:66])
shA = []
for i in range(4):
    shA.append(((A1[i].transpose())*A2[i]*B2[i]*(B1[i].transpose())).det())
print(shA)  
~~~

2.dbt学长的解法我觉得很棒，据说整活三行代码就搞定了，学不来）），但是我觉得这才是正解，我的思路其实大部分时候是不奏效的，总是和pk和sk正面去刚，感觉并不是什么时候都能做出来的，就比如说接下来的sums）），应该去找一些弱一点的性质（这是dbt学长原话）。
感觉dbt学长最后应该会放wp，所以就当是预告，期待一下。
## Modular 
签到题，不想写，大家自己看看exp吧：

~~~ python
from data import t,h,p 
m = len(t)
s = Matrix(ZZ, m+3 ,m+2)
for i in range(m):
    s[i, i] = p
    s[-3, i] = t[i]
    s[-2,i] = h[i]
    s[-1,i] = h[i]*t[i]
    
s[-2,-2] = 1
s[-1,-1] = 2**2048
s = s.BKZ(block_size = 10)
k = 0 
for i in range(m+3):
    v = s[i]
    if v[-1] == 2**2048:
        s = v[-2]

print(bytes_to_long(sha256(long_to_bytes(s)).digest()[:16]))
~~~

得到shared_secret,直接AES正常解密就行。

## Sums（赛后解出，作为思路分享）

就像开头说的，我最开始揪着背包格嗯解，哪怕我算出来他背包密度是大于1的，几乎没有解的可能，但是我还坚持认为，这应该是背包格的问题，重点在于格子构造的，怎么去优化这个格子以及后面bkz的调参。
我觉得Oracle学长给我放水了，可能因为已经到赛后了，Oracle学长直接否定了我的想法，我后面开始关注解密的方式，而且找到了这个加密系统的论文，所以这道题目最后对于我而言就是一道论文题，所有论文链接都放下面了：

[MHK](https://ieeexplore.ieee.org/document/6530389)

[MHK2](https://ieeexplore.ieee.org/document/6979893)

然后在这里锤一下两位学长，让我sums做题感受极其不好！！！为啥给我那么多hint，就差帮我写代码了……(~~我就有嘴说，没胆做的，所以两位学长大人有大量……~~)


根据论文我们可以知道解密如下：
$m ＝e^{-1}c \% p \% 2$

接下来就是如何求解e的问题，注意到加密函数中：

$\vec{a} = e*\vec{s}  \% p $  即，$\vec{a} = e\vec{s} + p\vec{k} $

但是$e ,p, \vec{s}$都未知，怎么去攻击呢？我们亲爱（~~咬牙切齿~~）的Oracle学长给出了提示，然后我找到了相应的攻击方法：
[Equivalent key attack](https://ietresearch.onlinelibrary.wiley.com/doi/pdfdirect/10.1049/iet-ifs.2018.0041?download=true)

大概思路是根据LLL（格子的构造在论文里给的很清楚），即Algorithm 1找到 $\vec{a}$的 orthogonal lattice，也就是论文里说的$ℒ^⊥(a)$,得到
$ℒ^⊥(a) = eℒ^⊥(a)\vec{s} + pℒ^⊥(a)\vec{k} = 0$，

$p,e$非零且互质，根据论文可知，存在

<div align="center">

$ℒ₁ = {\vec{t} ∈ ℒ^⊥(a) | <\vec{s} \vec{t}> = 0}$

$ℒ₁ = {\vec{t} ∈ ℒ^⊥(a) | <\vec{p}, \vec{t}> = 0}$

</div>


而当 $||\vec{s}||*||\vec{t}||<p$ 时，存在 
<div align="center">

$ℒ ={\vec{t} ∈ ℒ^⊥(a) | <\vec{p}, \vec{t}> = 0 , <\vec{s}, \vec{t}> = 0} $

</div>

我们根据Algorithm 1找到这个$ℒ$。

>small tips：论文里提到，$ℒ^⊥(a)$中至少存在一个向量不符合上面说的情况，但是受Oracle学长[bbs](https://bbs.xdsec.org/d/956-l-teamxin-cheng-yuan-yu-bei-cheng-yuan-mei-zhou-ti-mu-fu-xian-xue-xi-nei-rong-zong-jie/3)的启发，我决定把最后一个去了（~~我猜的~~）,结果是好的，感觉有运气成分在

即 $\vec{t},\vec{s},\vec{a}$都存在于$ℒ$中，由Algorithm 1，我们可以找到这个lattice的basis记作 $\vec{u₁},\vec{u₂}$

<div align="center">

$s = x_1\vec{u₁} + x_2\vec{u₂},$

$k = y_1\vec{u₁} + y_2\vec{u₂},$

</div>

我们把这两个个式子代入上面的核心加密式，就可以得到

<div align="center">

$a = z_1\vec{u₁} +z_2\vec{u₂}$

$ = (ex_1 + py_1)\vec{u₁} +(ex_1 + py_1)\vec{u₂} $

</div>


所以根据一点点线代知识：

<div align="center">

$\begin{bmatrix}
x_1 & y_1 \\
x_2 & y_2 \\
\end{bmatrix}\cdot \begin{bmatrix}
e  \\
p  \\
\end{bmatrix} = \begin{bmatrix}
z_1  \\
z_2  \\
\end{bmatrix}$

</div>

我们现在要去解 $x_1,x_2,y_1,y_2,z_1，z_2$,但是很困难,自由变量是四个，论文里给的思路是直接爆破，时间复杂度不在多项式范围内，我没爆出来。

但是还有最开头的加密式：
$p = \sum s + 2$

可以得到：

$\sum a = -2e \% p$

说实话，在这我又又又又又遇到困境了,然后开始检索模式，搜索关于Equivalent key attack的东西，有一道题目和这个题目相似程度80%，不过那边是[MK2加密](https://blog.maple3142.net/2023/06/26/google-ctf-2023-writeups/#mhk2)，那边给出了最后一个式子（关于这个式子的证明也在里边）：

$|det(\begin{bmatrix}
x_1 & y_1 \\
x_2 & y_2 \\
\end{bmatrix})| = |x_1\cdot y_2 - x_2 \cdot y_1| =1$

本来想攒够六个式子，优雅地解出来，但是作为我眼里的论文题，当我找到上面的MHK2的那个题目的时候，这道题目就已经解出来了，解题exp如下：

~~~python
from sage.all import *
import ast
def find_ortho_zz(*vecs):
    assert len(set(len(v) for v in vecs)) == 1
    L = block_matrix(ZZ, [[matrix(vecs).T, matrix.identity(len(vecs[0]))]])
    print("LLL", L.dimensions())
    nv = len(vecs)
    L[:, :nv] *= 2**256
    L = L.LLL()
    ret = []
    for row in L:
        if row[:nv] == 0:
            ret.append(row[nv:])
    return matrix(ret)


def find_key(a):
    # a=e*s+p*k
    t1 = find_ortho_zz(a)
    assert t1 * vector(a) == 0
    # we assume that only t1[-1]*s!=0 and t1[-1]*k!=0
    # so the t1[:-1] is orthogonal to s and k
    # therefore s, k are spanned by u1, u2
    u1, u2 = find_ortho_zz(*t1[:-1])
    # suppose s=x1*u1+x2*u2, k=y1*u1+y2*u2
    # a=e*s+p*k=e*(x1*u1+x2*u2)+p*(y1*u1+y2*u2)
    #          =(e*x1+p*y1)*u1+(e*x2+p*y2)*u2
    #          =         v1*u1+         v2*u2
    v1, v2 = matrix([u1, u2]).solve_left(vector(a))
    print(f"{v1 = } {v2 = }")
    # now we expect to find integers x1, x2, y1, y2, e, p such that
    # matrix([
    #     [x1,y1],
    #     [x2,y2]
    # ])*vector([e,p])==vector([v1,v2])
    # sum(x1*u1+x2*u2)+2==p
    # so there are three equations and six unknowns

    # after some testing, I found that det([[x1,y1],[x2,y2]]) is either 1 or -1
    # so we have four equations and six unknowns, which means it is possible to reduce it to an single equation and two unknowns

    for det in [1, -1]:
        R = QQ["x1s, x2s, y1s, y2s, es, ps"]
        x1s, x2s, y1s, y2s, es, ps = R.gens()
        f1, f2 = matrix([[x1s, y1s], [x2s, y2s]]) * vector([es, ps]) - vector([v1, v2])
        f3 = x1s * y2s - x2s * y1s - det
        f4 = sum(x1s * u1 + x2s * u2) + 2 - ps
        gb = R.ideal([f1, f2, f3, f4]).groebner_basis()
        mul = reduce(lcm, [c.denom() for c, _ in gb[1]])
        eq = gb[1].resultant(f4, ps) * mul
        # this equations appear to be a linear equation in x1, x2
        # so we can solve it using LLL as x1, x2 are small
        print(eq)
        L = matrix(
            QQ,
            [
                [eq.constant_coefficient(), 1, 0, 0],
                [eq.coefficient({x1s: 1}), 0, 1, 0],
                [eq.coefficient({x2s: 1}), 0, 0, 1],
            ],
        )
        bounds = [1, 1, 2**66, 2**66]
        scale = [2**128 // x for x in bounds]
        Q = diagonal_matrix(scale)
        L *= Q
        L = L.LLL()
        L /= Q
        for row in L:
            if row[1] < 0:
                row = -row
            if row[0] == 0 and row[1] == 1:
                x1, x2 = row[2:]
                # while we should be able to plug the x1, x2 into the ideal the get full solution
                # but I found that the dimension of the ideal is 1, so we can't do that here
                # we just solve it manually
                s = (x1 * u1 + x2 * u2).change_ring(ZZ)
                p = sum(s) + 2
                e_cand1 = a[0] * pow(s[0], -1, p) % p
                e_cand2 = a[1] * pow(s[1], -1, p) % p
                if e_cand1 == e_cand2:
                    return s, e_cand1, p

s, e, p = find_key(a)

def decrypt_bit(c):
    M = pow(e, -1, p) * c % p
    return M % 2


def decrypt(c):
    plaintext_bin = ""
    for j in c:
        plaintext_bin += str(decrypt_bit(j))

    split_bin = [plaintext_bin[i : i + 7] for i in range(0, len(plaintext_bin), 8)]

    plaintext = ""
    for seq in split_bin:
        plaintext += chr(int(seq, 2))
    return plaintext


print(decrypt(c))

~~~


但是很遗憾，并没有真正地靠自己的脑子想出最后的答案，而是借助了别人的思路，虽然看起来是解出来了，但是真高兴不起来，一点都不过瘾（感觉hint太多啦！！！！），我觉得sums值得我花更多的时间去研究一下，算是对orthogonal lattice里的一个入门吧，感觉对格子了解又多了一点，之后要学的东西还很多。

总之是一次不总是愉快偶尔坐牢但是感触很深的ctf（~~胆大包天把minil当ctf入门了~~）










