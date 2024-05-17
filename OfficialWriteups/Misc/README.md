## miniLCTF 2024 Misc WriteUps

### 乐到不跑

简单的签到题

打开页面后，查看`main.js`，发现有注释`// references: http://localhost:8080/docs`，访问`/docs`可以得到带注释的api文档，根据文档写一个脚本发送请求即可，可以参考0x team的写法

也可以直接修改`main.js`，将上报的坐标改为自动生成的坐标序列即可

```javascript
/**
 * @param {Array<{lat: number, lon: number}>} _ckpts
 */ 
function* positionGenerator(_ckpts) {
    /** @type {Array<{lat: number, lon: number}>} */
    let ckpts = JSON.parse(JSON.stringify(_ckpts));
    let crt = 0;
    let nxt = 1;

    function calculateDistance(lat1, lon1, lat2, lon2) {
        const R = 6371e3; // metres
        const phi1 = lat1 * Math.PI / 180; // φ, λ in radians
        const phi2 = lat2 * Math.PI / 180;
        const dphi = (lat2-lat1) * Math.PI / 180;
        const dlam = (lon2-lon1) * Math.PI / 180;

        const a = Math.sin(dphi/2) * Math.sin(dphi/2) +
                  Math.cos(phi1) * Math.cos(phi2) *
                  Math.sin(dlam/2) * Math.sin(dlam/2);
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));

        return R * c; // in metres
    }

    function* interpolate(lat1, lon1, lat2, lon2, distance) {
        const total = calculateDistance(lat1, lon1, lat2, lon2);
        const step = distance / total;
        let t = 0;
        while (t < 1) {
            yield {
                lat: lat1 + t * (lat2 - lat1),
                lon: lon1 + t * (lon2 - lon1),
            };
            t += step;
        }
    }
    
    while (true) {
        let ckpt1 = ckpts[crt];
        let ckpt2 = ckpts[nxt];
        const generator = interpolate(ckpt1.lat, ckpt1.lon, ckpt2.lat, ckpt2.lon, 99); // not 100, fuck ieee 754
        for (const pos of generator) {
            yield pos;
        }
        crt = (crt + 1) % ckpts.length;
        nxt = (nxt + 1) % ckpts.length;
    }
}
```

### minijail

一个简单的任意文件读写

连上容器之后看到hint，发现这行代码**显然不是python，而是javascript**

尝试通过`console.log("test")`获得回显，发现不能正常返回文本，只能获取到`String`类型的长度，此时有两种思路

第一种思路是直接不使用这个特性，通过别的方法来输出文本，由于此类题目基本都是将标准输出流重定向到tcp流，因此只要能往fd=1中写入数据即可，通过`import("fs").then(f=>{...})`来获取文件系统api，发现有报错`No flag for you`，简单尝试后发现是关键词匹配，通过`"f"+"s"`或者`'\x66s'`等方法绕过即可，之后使用`f.writeSync(1, "some text...")`即可获得回显（此处发现`write`也是关键词，可以用`f['\x77riteSync']`绕过）

第二种思路是利用输出的字符串长度，通过`Object.keys(global)`获取所有全局变量的名称，然后对每个变量名称的每个字符，通过`.charCodeAt(index)`方法得到该字符的ascii值，再用`'a'.repeat(count)`转换成字符串，最后`console.log(new String(...))`输出，具体脚本实现参考0x team的writeup。通过此方法可以找到被藏起来的真正的`console.log()`，之后可以通过`Object.values(global)[index](...)`来调用

之后开始寻找flag，发现根目录下没有flag文件，则考虑在环境变量中，此时又有两种方法

第一种方法直接读`/proc/self/environ`，通过`f.readFileSync("/proc/self/environ")`读取即可（同样有关键词匹配，按照上面的方法绕过即可）

第二种方法通过`import("process").then(p=>{...})`，然后通过`p.env`获得环境变量（关键词绕过同上）

### HiddenSignin

本题为半取证的隐写题目，主要围绕“隐藏”一词设计题目各部分，考察选手的新信息获取能力、基本的解隐写和取证能力。

解题流程如下：

1. 注意到题面中含有 `The First Key is 65536/////洰驦栶椶昳湥顥氳椸洸汣敥鬹渳止敦騲驤攷騰昷朶杤湤氳阶氱橡止杤湣騷/////65536`，观察有 65536 字样，在线搜索解码工具，期望选手通过搜索 `65536 decode` 等关键词来获得解码工具；
2. 题附 `volume.hc` 文件，易根据扩展名搜索得到这是 VeraCrypt 加密卷，使用上一步解码得到的 key 解密该卷，获得文件 `keyinside.png`；
3. 使用解隐写工具（如 StegSolve）解出 LSB 上的 RGB 图像（Red/Green/Blue plane 0），获取 "The Second Key"；
4. 联想到其与 "First Key" 之间的关系， 考虑用这个 key 二次解密 VeraCrypt 卷，此处利用到了 VeraCrypt 的 Hidden Volume 特性；
5. 挂载后的卷中的 `Flag.txt` 并不包含真实的 Flag，此时有两种思路：
    1. 使用取证软件打开该卷，易得回收站中的 RealFlag；使用非 Windows 系统的文件管理器打开同理；
    2. 发现 `Flag.txt` 的大小与实际内容不符，易发现字中夹带零宽 Unicode 文字，搜索并使用 [这个工具](https://www.mzy0.com/ctftools/zerowidth1/) 即可解出 hint，跟随 hint 查找回收站即可得到回收站中的 RealFlag。

### WeirdChat

本题为流量分析题，聚焦于基于 HTTP 的聊天协议 [Matrix](https://matrix.org/)，考察选手的新信息获取能力、流量分析基本功和新工具利用。

比赛过程中，出题人向校内同学依次放出了三个 Hint：

> Hint 1 本题是 Matrix 协议的 HTTP 流量分析题，这一协议以外的流量均不纳入本题解题过程的考虑范围。
Matrix 是一个默认端到端加密的聊天协议，这也就是说，**默认情况下**，即使它运行在明文的 HTTP 上，即使中间人捕获了用户的密码，也无法仅凭用户的密码解密消息。除非……
>
> Hint 2 ……除非消息根本就没有加密。
>
> Hint 3 在流量的靠后的位置，我们的主角创建了一个未加密的房间，并且以明文形式上传了**某些重要的东西**。

大致解题过程为：

1. 观察流量，发现主要为 HTTP 协议，过滤掉小包，在留下的流量包中发现发送的加密和未加密的消息，通过适当的过滤器或脚本将其提取出；
2. 流量最后含有未加密的消息，其中含有 `element-key.txt` 和密码 `MySuperSecretKey`；
3. 期望选手通过搜索引擎搜索与 `matrix message decrypt` 相关的工具，通过安装运行或适当的修改来达到目的；但同时也鼓励选手直接阅读 [Specification](https://spec.matrix.org/v1.10/client-server-api/#key-exports) 与使用 [Olm 加密库](https://gitlab.matrix.org/matrix-org/olm) 来完成消息的解密；
4. 解密到的消息里含有 Base32 编码的信息，解码后得到 Flag。

出题人在验题过程中使用或参考的源码：[Key Backup 解密工具](https://github.com/cyphar/matrix-utils/blob/main/megolm_backup.py)、[消息解密工具](https://github.com/vidister/matrix-message-decrypter/)。后者不能直接使用，可以参照它进行一些修改或使用 Olm 加密库重写。在这里推荐参考 Team 0x 的 WriteUp。

**思考题：**

Matrix 的密钥备份分为两种，一种是本题的导出至文件的 [Key Export](https://spec.matrix.org/v1.10/client-server-api/#key-exports)，另一种是直接上传到服务器的 [Server-side key backups](https://spec.matrix.org/v1.10/client-server-api/#server-side-key-backups)。设想如下的场景：不再导出 Key Export 而转而使用 Server-side key backups，中间人是否还能有机会解开备份的加密？

<details>
<summary>思路</summary>

Matrix 的 Server-side key backups 可以通过两种方式存储到服务器，一种是生成一对非对称密钥进行加密，此时解密备份的私钥被称为 Recovery Key，这种情况下，如果用户侧的 Recovery Key 泄露，则仍可以对流量中的备份请求进行解密。

另一种是使用 Matrix 服务器的 [Secrets](https://spec.matrix.org/v1.10/client-server-api/#secrets) 模块，这种情况下，客户端会对上述生成的 Recovery Key 使用一个随机生成（或从密码派生）的密钥加密上传到服务器以便分享。如果加密 Recovery Key 的密钥（或用以派生密钥的密码）被中间人获知，则可以解密 Recovery Key，进而解密流量中的备份请求。你也许会好奇这种加密方式是否属于多此一举，然而 Secrets 模块能使得在 Matrix 协议中的跨设备传输端到端加密密钥变得更为简单。

也请牢记本题的大前提条件是，我们搭建的出题环境运行在明文的 HTTP 上。因此，无论你在运行什么样的网站，请保证自己的站点配置了 HTTPS，来防止心怀不轨的中间人偷窥你的流量，窃取你的信息。

</details>
