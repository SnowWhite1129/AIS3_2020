import dis, marshal

def readflag():
    f = open('flag.txt')
    flag = f.read()
    return flag

def printflag(music):
    pt = keystone - 'a'
    a = 261.63
    note= [61, 63, 87]
    flag = readflag() 
    if music == True:
        print(flag)
        return

f = open('./rose.pyc', 'rb')
f.read(4)
f.read(4)

code = marshal.load(f)
print(code.co_consts)

print(code.co_varnames)

print(code.co_names)

dis.dis(code.co_code)
