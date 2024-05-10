import random

code = open('main.s').read().split('\n')

shit = ["""
    pushfq
    call\t$+7
    leave
    ret
    add\trsp, 8
    popfq
"""]

res = ""
for line in code:
    line = line.strip()
    if line == "":      # 空行直接略过
        continue
    elif ':' in line or line[0] == '.':   # 非代码行原样不动
        res += '\t' + line.strip() + '\n'
    elif 'cmp' in line or 'test' in line:
        res += '\t' + line.strip() + '\n'
    else:
        res += '\t' + line.strip()
        res += random.choice(shit)
open("fxxk.s", "w").write(res)
