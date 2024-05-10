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