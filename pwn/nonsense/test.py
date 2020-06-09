from pwn import *

#print(asm('mov eax, 0'))
#print(asm("ja 0x601117", arch='amd64', os='linux'))
print(asm("jmp edi", arch='amd64', os='linux'))

