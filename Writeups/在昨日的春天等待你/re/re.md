## Long long call

ida打开直接识别不了，看汇编是每个指令之间插了花，直接idc启动

```c
#include<idc.idc>
static main()
{
    auto start = 0x10E0;
    auto end = 0x1E31;
    auto i = 0,j;
    for(i = start; i < end;i = i + 1)
    {
        if(dword(i) == 0x08C48348)
        {
            Message("%x ",byte(i));
            for(j = 0; j < 5;j ++)
            {
                PatchByte(i+j,0x90);
            }

        }
        if(dword(i) == 0x002E89C && Byte(i + 6) == 0xC9)
        {
            Message("%x ",byte(i));
            for(j = 0; j < 8;j ++)
            {
                PatchByte(i+j,0x90);
            }

        }
         //Message("%x ",byte(i));
    }
}
```

重新识别得到非常清晰且简单的加密流程

<img src="file:///D:/CTF/Mini_L_2024/re/picture/1-2.png" title="" alt="" data-align="left">

![](file:///D:/CTF/Mini_L_2024/re/picture/1-1.png)

开爆

```c
#include<iostream>
using namespace std;
unsigned char enc[] =
{
  0xBB, 0xBF, 0xB9, 0xBE, 0xC3, 0xCC, 0xCE, 0xDC, 0x9E, 0x8F, 
  0x9D, 0x9B, 0xA7, 0x8C, 0xD7, 0x95, 0xB0, 0xAD, 0xBD, 0xB4, 
  0x88, 0xAF, 0x92, 0xD0, 0xCF, 0xA1, 0xA3, 0x92, 0xB7, 0xB4, 
  0xC9, 0x9E, 0x94, 0xA7, 0xAE, 0xF0, 0xA1, 0x99, 0xC0, 0xE3, 
  0xB4, 0xB4, 0xBF, 0xE3
};
int main()
{
/*    for (int i = 0; i <= 43; i += 2 )
      {
    v2 = a1[i] + a1[i + 1];
    a1[i] ^= v2;
    a1[i + 1] ^= v2;
      }*/
      unsigned char a,b,c;
      for (int i = 0; i <= 43; i += 2 )
      {
        for(int k=32;k<=127;k++)
        {
            for(int j=32;j<=127;j++)
            {
                a=(k+j);
                b=k^a;
                c=j^a;
                if(b==enc[i]&&c==enc[i+1])
                {
                    printf("%c%c",k,j);
                }
            }
        }
      }
}
//miniLCTF{just_s1mple_x0r_1n_lon9_l0ng_c@ll!}
```



## Bigbanana

一道非常标准的C语言VM题，不是伪随机控制流，不是系统调用VM，不是RUST VM，不是异常处理控制流，不是栈溢出控制流，真的哭死

一边哭一边写敲下代码

```c
#include<iostream>
#include<stdint.h>
using namespace std;
unsigned char opcode[] =
{
 ...
};
int main()
{
    unsigned int a,b;
    int eip=0,op = 1;
    while ( op )
  {
      op = opcode[eip];
    switch ( op-1 )
    {
    case 0:
        a=*((uint32_t*)&opcode[eip+4]);
        //ADD(eax_, eip_ + 4);
        printf("Add(eax,%d) \n",a);
        eip += 8;
        break;
      case 0xF:
        //input[0] = 0;
        //input[0] = getchar();
        //INPUT(input);
        printf("    Input(reg[i]) \n");
        printf("i++ \n");
        eip += 4;
        break;
      case 0x10:
        //PRINT(&unk_14001BF4C);
        printf("Print() \n");
        eip += 4;
        break;
      case 0xEF:
       // MOV(ebx_, eax_);
        printf("Mov(ebx,eax) \n");
        eip += 4;
        break;
      case 0xF0:
        //MOV(ebp_, eax_);
        printf("Mov(ebp,eax) \n");
        eip += 4;
        break;
      case 0xF1:
        //CMP(ebx_, eip_ + 4);
        a=*((uint32_t*)&opcode[eip+4]);
        printf("Cmp(ebx,%d) \n",a);
        eip += 8;
        break;
      case 0xF2:
        //XOR(ebx_, eax_);
        eip += 4;
        printf("Xor(ebx,eax) \n");
        break;
      case 0xF3:
        //ADD(ebx_, eip_ + 4);
        a=*((uint32_t*)&opcode[eip+4]);
        printf("Add(ebx,%d) \n",a);
        eip += 8;
        break;
      case 0xF4:
        //SUB(eip_ + 4, eip_ + 8);
        a=*((uint32_t*)&opcode[eip+4]);
        b=*((uint32_t*)&opcode[eip+8]);
        printf("Sub(%d,%d) \n",a,b);
        eip += 12;
        break;
      case 0xF5:
        //INPUT(eip_ + 4);
        a=*((uint32_t*)&opcode[eip+4]);
        printf("Mov(reg[i],%d) \n",a);
        printf("i++ \n");
        eip += 8;
        break;
      case 0xF6:
        //MOV_REG(ebx_);
        printf("Mov(ebx,reg[i]) \n");
        printf("i-- \n");
        eip += 4;
        break;
      case 0xF7:
        //MOV_REG(eax_);
        printf("Mov(eax,reg[i]) \n");
        printf("i-- \n");
        eip += 4;
        break;
      case 0xF8:
        //MOV_REG(ecx_);
        printf("Mov(ecx,reg[i]) \n");
        printf("i-- \n");
        eip += 4;
        break;
      case 0xF9:
        //MOV_REG(ebp_);
        printf("Mov(ebp,reg[i]) \n");
        printf("i-- \n");
        eip += 4;
        break;
      case 0xFD:
        //JUDGE_FALSE(eip_ + 4);
        printf("Judge_False \n");
        eip += 8;
        break;
      case 0xFE:
        printf("Judge_True \n");
        eip += 8;
        break;
      default:
        break;
    }
  }
}
```

然后发现前面的一大串流程都是用来输出一句话的，毛用没有，真的有用的是从eip=2888的input开始，那就手动修改一下，顺便改成z3的格式

```c
#include<iostream>
#include<stdint.h>
using namespace std;
unsigned char opcode[] =
{
  ...
};
int main()
{
    unsigned int a,b;
    int eip=2888,op = 1;
    int index = 0;
    while ( op )
  {
      op = opcode[eip];
    switch ( op-1 )
    {
    case 0:
        a=*((uint32_t*)&opcode[eip+4]);
        //ADD(eax_, eip_ + 4);
        printf("eax += 0x%x \n",a);
        eip += 8;
        break;
      case 0xF:
        //input[0] = 0;
        //input[0] = getchar();
        //INPUT(input);
        //printf("    Input(reg[i]) \n");
        //printf("i++ \n");
        eip += 4;
        break;
      case 0x10:
        //PRINT(&unk_14001BF4C);
        printf("Print() \n");
        eip += 4;
        break;
      case 0xEF:
       // MOV(ebx_, eax_);
        printf("ebx = eax \n");
        eip += 4;
        break;
      case 0xF0:
        //MOV(ebp_, eax_);
        printf("Mov(ebp,eax) \n");
        eip += 4;
        break;
      case 0xF1:
        //CMP(ebx_, eip_ + 4);
        a=*((uint32_t*)&opcode[eip+4]);
        printf("s.add(ebx == 0x%x) \n",a);
        eip += 8;
        break;
      case 0xF2:
        //XOR(ebx_, eax_);
        eip += 4;
        printf("ebx ^= eax \n");
        break;
      case 0xF3:
        //ADD(ebx_, eip_ + 4);
        a=*((uint32_t*)&opcode[eip+4]);
        printf("ebx += 0x%x \n",a);
        eip += 8;
        break;
      case 0xF4:
        //SUB(eip_ + 4, eip_ + 8);
        a=*((uint32_t*)&opcode[eip+4]);
        b=*((uint32_t*)&opcode[eip+8]);
        printf("Sub(%d,%d) \n",a,b);
        eip += 12;
        break;
      case 0xF5:
        //INPUT(eip_ + 4);
        a=*((uint32_t*)&opcode[eip+4]);
        printf("Mov(reg[i],%d) \n",a);
        //printf("i++ \n");
        eip += 8;
        break;
      case 0xF6:
        //MOV_REG(ebx_);
        printf("ebx = input[%d] \n",index);
        index++;
        //printf("i-- \n");
        eip += 4;
        break;
      case 0xF7:
        //MOV_REG(eax_);
        //if(eax)

        printf("eax = input[%d] \n",index);
        index++;
        //printf("i-- \n");
        eip += 4;
        break;
      case 0xF8:
        //MOV_REG(ecx_);
        printf("Mov(ecx,reg[i]) \n");
        //printf("i-- \n");
        eip += 4;
        break;
      case 0xF9:
        //MOV_REG(ebp_);
        printf("Mov(ebp,reg[i]) \n");
        //printf("i-- \n");
        eip += 4;
        break;
      case 0xFD:
        //JUDGE_FALSE(eip_ + 4);
        //printf("Judge_False \n");
        eip += 8;
        break;
      case 0xFE:
        //printf("Judge_True \n");
        eip += 8;
        break;
      default:
        break;
    }
  }
}
```

然后直接z3启动，感觉这里有点奇怪，加了input > 32的条件可以爆出flag，但加了input < 128就不行

```python
from z3 import *

input = [BitVec('input[%d]' % i, 8) for i in range(46)]
s=Solver()

for i in range(45):
    s.add(input[i] > 32)

eax = input[0]
ebx = input[1]
ebx += 0x694e694d
eax += 0x74632d4c
ebx += 0x0
ebx ^= eax
s.add(ebx == 0x1d2d440f)
ebx = eax
eax = input[2]
ebx += 0x16
eax += 0x21
ebx += 0x114514
ebx ^= eax
s.add(ebx == 0x74747250)
ebx = eax
eax = input[3]
ebx += 0x21
eax += 0x2c
ebx += 0x228a28
ebx ^= eax
s.add(ebx == 0x228a4d)
ebx = eax
eax = input[4]
ebx += 0x2c
eax += 0xb
ebx += 0x33cf3c
ebx ^= eax
s.add(ebx == 0x33cfaa)
ebx = eax
eax = input[5]
ebx += 0xb
eax += 0x16
ebx += 0x451450
ebx ^= eax
s.add(ebx == 0x4514cb)
ebx = eax
eax = input[6]
ebx += 0x16
eax += 0x21
ebx += 0x565964
ebx ^= eax
s.add(ebx == 0x565966)
ebx = eax
eax = input[7]
ebx += 0x21
eax += 0x2c
ebx += 0x679e78
ebx ^= eax
s.add(ebx == 0x679fbc)
ebx = eax
eax = input[8]
ebx += 0x2c
eax += 0xb
ebx += 0x78e38c
ebx ^= eax
s.add(ebx == 0x78e4cc)
ebx = eax
eax = input[9]
ebx += 0xb
eax += 0x16
ebx += 0x8a28a0
ebx ^= eax
s.add(ebx == 0x8a2949)
ebx = eax
eax = input[10]
ebx += 0x16
eax += 0x21
ebx += 0x9b6db4
ebx ^= eax
s.add(ebx == 0x9b6ec8)
ebx = eax
eax = input[11]
ebx += 0x21
eax += 0x2c
ebx += 0xacb2c8
ebx ^= eax
s.add(ebx == 0xacb3e0)
ebx = eax
eax = input[12]
ebx += 0x2c
eax += 0xb
ebx += 0xbdf7dc
ebx ^= eax
s.add(ebx == 0xbdf8f6)
ebx = eax
eax = input[13]
ebx += 0xb
eax += 0x16
ebx += 0xcf3cf0
ebx ^= eax
s.add(ebx == 0xcf3d22)
ebx = eax
eax = input[14]
ebx += 0x16
eax += 0x21
ebx += 0xe08204
ebx ^= eax
s.add(ebx == 0xe082eb)
ebx = eax
eax = input[15]
ebx += 0x21
eax += 0x2c
ebx += 0xf1c718
ebx ^= eax
s.add(ebx == 0xf1c745)
ebx = eax
eax = input[16]
ebx += 0x2c
eax += 0xb
ebx += 0x1030c2c
ebx ^= eax
s.add(ebx == 0x1030c9c)
ebx = eax
eax = input[17]
ebx += 0xb
eax += 0x16
ebx += 0x1145140
ebx ^= eax
s.add(ebx == 0x114518e)
ebx = eax
eax = input[18]
ebx += 0x16
eax += 0x21
ebx += 0x1259654
ebx ^= eax
s.add(ebx == 0x1259634)
ebx = eax
eax = input[19]
ebx += 0x21
eax += 0x2c
ebx += 0x136db68
ebx ^= eax
s.add(ebx == 0x136dc9c)
ebx = eax
eax = input[20]
ebx += 0x2c
eax += 0xb
ebx += 0x148207c
ebx ^= eax
s.add(ebx == 0x148217d)
ebx = eax
eax = input[21]
ebx += 0xb
eax += 0x16
ebx += 0x1596590
ebx ^= eax
s.add(ebx == 0x15965ae)
ebx = eax
eax = input[22]
ebx += 0x16
eax += 0x21
ebx += 0x16aaaa4
ebx ^= eax
s.add(ebx == 0x16aabb8)
ebx = eax
eax = input[23]
ebx += 0x21
eax += 0x2c
ebx += 0x17befb8
ebx ^= eax
s.add(ebx == 0x17bf02f)
ebx = eax
eax = input[24]
ebx += 0x2c
eax += 0xb
ebx += 0x18d34cc
ebx ^= eax
s.add(ebx == 0x18d352a)
ebx = eax
eax = input[25]
ebx += 0xb
eax += 0x16
ebx += 0x19e79e0
ebx ^= eax
s.add(ebx == 0x19e7ae7)
ebx = eax
eax = input[26]
ebx += 0x16
eax += 0x21
ebx += 0x1afbef4
ebx ^= eax
s.add(ebx == 0x1afbf19)
ebx = eax
eax = input[27]
ebx += 0x21
eax += 0x2c
ebx += 0x1c10408
ebx ^= eax
s.add(ebx == 0x1c1043c)
ebx = eax
eax = input[28]
ebx += 0x2c
eax += 0xb
ebx += 0x1d2491c
ebx ^= eax
s.add(ebx == 0x1d249a4)
ebx = eax
eax = input[29]
ebx += 0xb
eax += 0x16
ebx += 0x1e38e30
ebx ^= eax
s.add(ebx == 0x1e38e3e)
ebx = eax
eax = input[30]
ebx += 0x16
eax += 0x21
ebx += 0x1f4d344
ebx ^= eax
s.add(ebx == 0x1f4d3b0)
ebx = eax
eax = input[31]
ebx += 0x21
eax += 0x2c
ebx += 0x2061858
ebx ^= eax
s.add(ebx == 0x2061853)
ebx = eax
eax = input[32]
ebx += 0x2c
eax += 0xb
ebx += 0x2175d6c
ebx ^= eax
s.add(ebx == 0x2175e76)
ebx = eax
eax = input[33]
ebx += 0xb
eax += 0x16
ebx += 0x228a280
ebx ^= eax
s.add(ebx == 0x228a241)
ebx = eax
eax = input[34]
ebx += 0x16
eax += 0x21
ebx += 0x239e794
ebx ^= eax
s.add(ebx == 0x239e866)
ebx = eax
eax = input[35]
ebx += 0x21
eax += 0x2c
ebx += 0x24b2ca8
ebx ^= eax
s.add(ebx == 0x24b2d81)
ebx = eax
eax = input[36]
ebx += 0x2c
eax += 0xb
ebx += 0x25c71bc
ebx ^= eax
s.add(ebx == 0x25c72f0)
ebx = eax
eax = input[37]
ebx += 0xb
eax += 0x16
ebx += 0x26db6d0
ebx ^= eax
s.add(ebx == 0x26db738)
ebx = eax
eax = input[38]
ebx += 0x16
eax += 0x21
ebx += 0x27efbe4
ebx ^= eax
s.add(ebx == 0x27efcfc)
ebx = eax
eax = input[39]
ebx += 0x21
eax += 0x2c
ebx += 0x29040f8
ebx ^= eax
s.add(ebx == 0x29041f1)
ebx = eax
eax = input[40]
ebx += 0x2c
eax += 0xb
ebx += 0x2a1860c
ebx ^= eax
s.add(ebx == 0x2a186e7)
ebx = eax
eax = input[41]
ebx += 0xb
eax += 0x16
ebx += 0x2b2cb20
ebx ^= eax
s.add(ebx == 0x2b2cbe3)
ebx = eax
eax = input[42]
ebx += 0x16
eax += 0x21
ebx += 0x2c41034
ebx ^= eax
s.add(ebx == 0x2c4105d)
ebx = eax
eax = input[43]
ebx += 0x21
eax += 0x2c
ebx += 0x2d55548
ebx ^= eax
s.add(ebx == 0x2d55595)
ebx = eax
eax = input[44]
ebx += 0x2c
eax += 0xb
ebx += 0x2e69a5c
ebx ^= eax
s.add(ebx == 0x2e69a7b)


if sat == s.check():
    ans = s.model()
    for i in range(45):
        print(chr(ans[input[i]].as_long()),end="")
#imniLctf{bigb4nan4_i5_v3ry_int3r5t1ng_r1ght?}
```

最后输出的m和i位置有点奇怪，换一下就好了



## RustedRobot

jeb打开发现是调用了native层的函数，找到so文件，ida打开解析了非常久，发现是用rust写的之后人都吓尿了，然后发现又加载了java层的类，

于是先回去看看



![2](D:\CTF\Mini_L_2024\re\picture\2.png)

构造一个全是'a'的输入，开始动调动调，发现运行到这个类的加密方法里，明文全变成了'b'，然后key拿到

![](file:///D:/CTF/Mini_L_2024/re/picture/2-1.png)

再构造一个输入，猜测就是先将密文每位+1，然后倒置再aes，厨子梭哈一波

![](file:///D:/CTF/Mini_L_2024/re/picture/2-2.png)

梭哈一下，真的出来了，出题人好温柔，居然没在rust搞事，我哭死

```c
#include<iostream>
using namespace std;
unsigned char enc[]="~u1c1s`E4UTVS|GUDMjojn";
int main()
{
    for(int i=sizeof(enc)-2;i>=0;i--)
    {
        enc[i]-=1;
        printf("%c",enc[i]);
    }
}
//miniLCTF{RUST3D_r0b0t}
```



## OllessVM

某位知名逆向大神曾经说过：技巧只会增加手撕的速度

虽然程序用了某种强大的混淆技术让人完全看不懂，但只要动调就可以解决

```c
#include<iostream>
using namespace std;
unsigned char key[] =
{
  0x91, 0x99, 0x41, 0x7B, 0x79, 0x81, 0x4B, 0xCB, 0xA9, 0xEC, 
  0x2E, 0x02, 0xCB, 0x94, 0xE5, 0x26, 0x91, 0x0B, 0xA6, 0x0F, 
  0x28, 0x81, 0xA1, 0x60, 0xD1, 0x52, 0x5F, 0xC4, 0x7A, 0xAD, 
  0x4F, 0xFF, 0xE2, 0x99, 0xD5, 0x7A, 0x28, 0x6E, 0xC0, 0x37, 
  0xF5, 0x70, 0xE6, 0x46, 0x07, 0x07, 0xA2, 0xF5, 0x4B, 0x39, 
  0x3A, 0x97, 0x32, 0x8E, 0xB0, 0xE7, 0xBB, 0xE8, 0xC7, 0xD2, 
  0xB7, 0x08, 0x7B, 0x62, 0x66, 0xC0, 0x18, 0x03, 0x0B, 0x5B, 
  0x00, 0x00, 0xA0, 0xF4, 0x98, 0x6B, 0x46, 0x02, 0x46, 0x02, 
  0xE0, 0xF9, 0xDA, 0x77, 0x38, 0x00, 0x00, 0x00, 0x5B, 0xA7, 
  0x32, 0x9A, 0xF7, 0x7F, 0x00, 0x00, 0x90, 0xFA, 0xDA, 0x77, 
  0x38
};
unsigned char enc[] =
{
  0xFC, 0xF1, 0x2D, 0x11, 0x31, 0xC7, 0x19, 0x8A, 0xDA, 0xBC, 
  0x14, 0x7C, 0x98, 0xEA, 0xDB, 0x65, 0xF7, 0x29, 0xD0, 0x43, 
  0x48, 0xFC, 0x84, 0x28, 0xF9, 0x29, 0x23, 0xAC, 0x59, 0xCD, 
  0x51, 0xE0, 0xC2, 0xB8, 0xF7, 0x59, 0x0C, 0x4B, 0xE6, 0x10, 
  0xDD, 0x59, 0xCC, 0x6D, 0x2B, 0x2A, 0x8C, 0xDA, 0x7B, 0x08, 
  0x08, 0xA4, 0x06, 0xBB, 0x86, 0xD0, 0x83, 0xD1, 0xFD, 0xE9, 
  0x8B, 0x35, 0x45, 0x5D, 0x51, 0x4C, 0xD1, 0x72, 0xF6, 0xB8, 
  0xE6, 0x9E, 0xE2, 0xB7, 0x2D, 0x75, 0x25, 0x71, 0x2B, 0x4B, 
  0x86, 0x45, 0x87, 0xA1, 0xC9, 0x47, 0xC5, 0x5A, 0x16, 0x5E, 
  0x1A, 0xD1, 0x17, 0x9D, 0x18, 0x6E, 0x3F, 0xD2, 0x75, 0xE9, 
  0xE3, 0x51, 0x56, 0xC2, 0x06, 0x04, 0x6D, 0x1A, 0x50, 0x65, 
  0x7D, 0xFD, 0xA9, 0x12
};
int main()
{
    unsigned char a;
    for(int i=0;i<30;i++)
    {
        a=enc[i]^key[i]^i;
        printf("%c",a);
    }
}
//miniLCTF{Y0u_s0Lv3d_th3_0bfs?}
```



## OBF_REVENGE

re手狂喜，这下完全不用想着怎么去混淆了，可以一心一意地动调了(

加密流程：

```c
#include <stdio.h>
#include <stdint.h>
#define DELTA 0xBADECADA
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))

void btea(uint32_t* v, int n, uint32_t const key[4])
{
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    if (n > 1)            /* Coding Part */
    {
        rounds = 6 + 52 / n;

        sum = 0;
        z = v[n - 1];
        do
        {
            sum += DELTA;
            e = (sum >> 2) & 3;
            for (p = 0; p < n - 1; p++)
            {
                y = v[p + 1];
                z = v[p] += (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)));
            }
            y = v[0];
            z = v[n - 1] += (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)));
        } while (--rounds);
    }
    else if (n < -1)      /* Decoding Part */
    {
        n = -n;
        rounds = 6 + 52 / n;
        sum = rounds * DELTA;
        //printf("%d\n",rounds);
        y = v[0];
        do
        {
            e = (sum >> 2) & 3;
            for (p = n - 1; p > 0; p--)
            {
                z = v[p - 1];
                y = v[p] -= MX;
            }
            z = v[n - 1];
            y = v[0] -= MX;
            sum -= DELTA;
        } while (--rounds);
    }
}

unsigned char enc[] = "miniLCTF{Aru5T3d_h3ll_REVERSERS}";
unsigned char encs[32];


int main()
{
    uint32_t const k[4] = { 0x08040201,0x80402010,0xF8FCFEFF,0x80C0E0F0 };
    unsigned char *key=(unsigned char*)k;
	uint32_t v[8];


    for (int i = 0; i <= 32; i++)
    {
        
        enc[i] ^= key[i%16] ;
    }

    for (int i = 0; i < 8; i++)
    {
        v[i] = *((uint32_t*)&enc[i * 4]);
    }

    int n = 8; 
    btea(v, n, k);
    
    unsigned char*pv = (unsigned char*)v;
    
    for (int i = 0; i < 32; i++)
    {
        pv[i] ^= key[(31-i)%16];
        encs[31-i] = pv[i];
    }
    
    for(int i=0;i<32;i++)
    {
    	encs[i] ^= 0x18;
    	printf("%X ",encs[i]);
	}
    
    
    return 0;
};
```

exp:

```c
#include <stdio.h>
#include <stdint.h>
#define DELTA 0xBADECADA
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))

void btea(uint32_t* v, int n, uint32_t const key[4])
{
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    if (n > 1)            /* Coding Part */
    {
        rounds = 6 + 52 / n;

        sum = 0;
        z = v[n - 1];
        do
        {
            sum += DELTA;
            e = (sum >> 2) & 3;
            for (p = 0; p < n - 1; p++)
            {
                y = v[p + 1];
                z = v[p] += (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)));
            }
            y = v[0];
            z = v[n - 1] += (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)));
        } while (--rounds);
    }
    else if (n < -1)      /* Decoding Part */
    {
        n = -n;
        rounds = 6 + 52 / n;
        sum = rounds * DELTA;
        y = v[0];
        do
        {
            e = (sum >> 2) & 3;
            for (p = n - 1; p > 0; p--)
            {
                z = v[p - 1];
                y = v[p] -= MX;
            }
            z = v[n - 1];
            y = v[0] -= MX;
            sum -= DELTA;
        } while (--rounds);
    }
}

unsigned char encs[] = {    0x4B, 0xA0, 0x0C, 0xFF, 0xAB, 0x0A, 0x13, 0xB0, 0x32, 0x91,
0x6D, 0x87, 0x8B, 0xAB, 0xF5, 0xA5, 0xDC, 0x77, 0xD4, 0x95,
0xB9, 0x02, 0xA6, 0xAC, 0xE4, 0x74, 0x2C, 0x6B, 0xEB, 0xE1,
0x5E, 0x25};

unsigned char enc[32];


int main()
{
    uint32_t const k[4] = { 0x08040201,0x80402010,0xF8FCFEFF,0x80C0E0F0 };
    unsigned char *key=(unsigned char*)k;
	uint32_t v[8];

	for(int i=0;i<32;i++)
    {
    	encs[i] ^= 0x18;
	}
	
	for(int i=0;i<32;i++)
	{
		enc[i] = encs[31-i];
		enc[i] ^= key[(31-i)%16];
	}  
	
	for(int i=0;i<8;i++)
	{
		v[i]=*((uint32_t *)&enc[i*4]);
	}

    int n = 8; 
    btea(v, -n, k);
    
    unsigned char*pv = (unsigned char*)v;
    
    for (int i = 0; i < 32; i++)
    {
        pv[i] ^= key[i%16];
        printf("%c",pv[i]);
    }
    return 0;
}
//miniLCTF{Aru5T3d_h3ll_REVERSERS}
```
